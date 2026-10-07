// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// The Kubernetes API is spoken directly rather than through client-go.
// That library alone pulls in more modules than this entire project has
// dependencies, and writing a Secret is one HTTP request — the same shape
// as the Cloudflare, AliDNS and Tencent calls already here.
const (
	// serviceAccountDir is where a pod finds its own credentials.
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	// fieldManager identifies our writes to server-side apply, so a field
	// this service owns is not fought over with whatever else edits the
	// Secret.
	fieldManager = "certcenter"
)

type k8sConfig struct {
	// Namespace and Name identify the Secret.
	Namespace string `json:"namespace"`
	Name      string `json:"name"`

	// Server, Token and CACert address a cluster from outside. Left empty,
	// the pod's own service account is used, which is the in-cluster case
	// and needs no configuration at all.
	Server string `json:"server"`
	Token  string `json:"token"`
	CACert string `json:"ca_cert"`
	// Insecure skips API server certificate verification. Present for a
	// cluster with a private CA the operator has not wired in; ca_cert is
	// the better answer.
	Insecure bool `json:"insecure"`

	// ChainInCert puts the intermediates in tls.crt alongside the leaf,
	// which is what ingress controllers expect. Turning it off stores the
	// leaf alone, for the rare consumer that wants them apart.
	LeafOnly bool `json:"leaf_only"`
}

type k8sClient struct {
	server string
	token  string
	client *http.Client
}

// newK8sClient resolves credentials: explicit config first, otherwise the
// pod's own service account.
func newK8sClient(cfg k8sConfig) (*k8sClient, error) {
	server, token, caPEM := cfg.Server, cfg.Token, cfg.CACert

	if server == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, fmt.Errorf(
				"no server given and this is not running inside a cluster; " +
					"set server, token and ca_cert to reach one from outside")
		}
		server = "https://" + host + ":" + port
	}
	if token == "" {
		raw, err := os.ReadFile(serviceAccountDir + "/token")
		if err != nil {
			return nil, fmt.Errorf("no token given and none readable from the service account: %w", err)
		}
		token = strings.TrimSpace(string(raw))
	}
	if caPEM == "" && !cfg.Insecure {
		if raw, err := os.ReadFile(serviceAccountDir + "/ca.crt"); err == nil {
			caPEM = string(raw)
		}
	}

	transport := &http.Transport{}
	switch {
	case cfg.Insecure:
		//nolint:gosec // deliberate: see the Insecure field's documentation
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case caPEM != "":
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("ca_cert is not a usable PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}

	return &k8sClient{
		server: strings.TrimSuffix(server, "/"),
		token:  token,
		client: &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

// apply performs a server-side apply, which creates or updates in one
// request. The alternative — PUT, and POST when that 404s — also has to
// carry a resourceVersion to avoid clobbering concurrent edits.
func (k *k8sClient) apply(ctx context.Context, path string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s%s?fieldManager=%s&force=true", k.server, path, fieldManager)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	// JSON is valid YAML, so the apply content type accepts what we built.
	req.Header.Set("Content-Type", "application/apply-patch+yaml")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("reach the Kubernetes API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The API's own message names the missing RBAC verb, which is the
		// usual cause and not something we could guess.
		return fmt.Errorf("Kubernetes API returned %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}
	return nil
}

func stepK8sSecret(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	var cfg k8sConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse k8s_secret config: %w", err)
	}
	if cfg.Name == "" {
		return fmt.Errorf("k8s_secret needs a name")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}

	client, err := newK8sClient(cfg)
	if err != nil {
		return err
	}

	// Ingress controllers expect the chain in tls.crt; storing the leaf
	// alone leaves clients to find the intermediates themselves, which
	// many will not.
	certPEM := st.cert.FullChainPEM()
	if cfg.LeafOnly {
		certPEM = st.cert.CertPEM
	}

	secret := map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      st.expand(cfg.Name),
			"namespace": st.expand(cfg.Namespace),
		},
		"type": "kubernetes.io/tls",
		"data": map[string]string{
			"tls.crt": base64.StdEncoding.EncodeToString([]byte(certPEM)),
			"tls.key": base64.StdEncoding.EncodeToString([]byte(st.cert.KeyPEM)),
		},
	}

	path := fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s",
		st.expand(cfg.Namespace), st.expand(cfg.Name))
	st.emit(Event{Type: StepK8sSecret, Level: LevelInfo,
		Message: fmt.Sprintf("Applying Secret %s/%s", cfg.Namespace, cfg.Name),
		Detail:  fmt.Sprintf("type kubernetes.io/tls, %d bytes of certificate", len(certPEM))})

	if err := client.apply(ctx, path, secret); err != nil {
		return err
	}
	st.emit(Event{Type: StepK8sSecret, Level: LevelSuccess,
		Message: fmt.Sprintf("Secret %s/%s updated", cfg.Namespace, cfg.Name)})
	return nil
}

type k8sRestartConfig struct {
	k8sConfig
	// Kind is deployment, statefulset or daemonset.
	Kind string `json:"kind"`
}

// stepK8sRestart rolls a workload so it picks up the new Secret.
//
// A pod holding a mounted Secret sees the new file eventually, but a
// server that read the certificate at startup keeps serving the old one
// until it restarts. This is what kubectl rollout restart does: stamp an
// annotation on the pod template so the controller replaces the pods.
func stepK8sRestart(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	var cfg k8sRestartConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse k8s_restart config: %w", err)
	}
	if cfg.Name == "" {
		return fmt.Errorf("k8s_restart needs a name")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	resource := map[string]string{
		"": "deployments", "deployment": "deployments",
		"statefulset": "statefulsets", "daemonset": "daemonsets",
	}[strings.ToLower(cfg.Kind)]
	if resource == "" {
		return fmt.Errorf("k8s_restart kind %q is not deployment, statefulset or daemonset", cfg.Kind)
	}

	client, err := newK8sClient(cfg.k8sConfig)
	if err != nil {
		return err
	}

	stamp := time.Now().UTC().Format(time.RFC3339)
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						"kubectl.kubernetes.io/restartedAt": stamp,
					},
				},
			},
		},
	}
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/%s/%s",
		st.expand(cfg.Namespace), resource, st.expand(cfg.Name))

	st.emit(Event{Type: StepK8sRestart, Level: LevelInfo,
		Message: fmt.Sprintf("Restarting %s %s/%s", resource, cfg.Namespace, cfg.Name)})

	if err := client.mergePatch(ctx, path, patch); err != nil {
		return err
	}
	st.emit(Event{Type: StepK8sRestart, Level: LevelSuccess,
		Message: fmt.Sprintf("Rollout triggered at %s", stamp)})
	return nil
}

// mergePatch touches named fields without owning the rest of the object,
// which is what a restart annotation wants — server-side apply would try
// to take ownership of the whole pod template.
func (k *k8sClient) mergePatch(ctx context.Context, path string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, k.server+path,
		strings.NewReader(string(encoded)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+k.token)

	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("reach the Kubernetes API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("Kubernetes API returned %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}
	return nil
}
