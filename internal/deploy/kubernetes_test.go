// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type captured struct {
	Method      string
	Path        string
	Query       string
	ContentType string
	Auth        string
	Body        map[string]any
}

// fakeAPIServer stands in for the Kubernetes API and records the request.
func fakeAPIServer(t *testing.T, status int, reply string) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Method, got.Path, got.Query = r.Method, r.URL.Path, r.URL.RawQuery
		got.ContentType = r.Header.Get("Content-Type")
		got.Auth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.Body)
		w.WriteHeader(status)
		w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func k8sStepConfig(t *testing.T, server string, extra map[string]any) json.RawMessage {
	t.Helper()
	cfg := map[string]any{
		"server": server, "token": "test-token", "insecure": true,
		"namespace": "web", "name": "example-tls",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestK8sSecretApplies(t *testing.T) {
	srv, got := fakeAPIServer(t, http.StatusOK, `{"kind":"Secret"}`)
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}

	if err := stepK8sSecret(context.Background(), st, k8sStepConfig(t, srv.URL, nil)); err != nil {
		t.Fatalf("stepK8sSecret = %v", err)
	}

	if got.Method != http.MethodPatch {
		t.Errorf("method = %s, want PATCH", got.Method)
	}
	if want := "/api/v1/namespaces/web/secrets/example-tls"; got.Path != want {
		t.Errorf("path = %q, want %q", got.Path, want)
	}
	// Server-side apply creates or updates in one call, so there is no
	// resourceVersion to fetch and no create/update branch.
	if !strings.Contains(got.ContentType, "apply-patch") {
		t.Errorf("Content-Type = %q, want a server-side apply", got.ContentType)
	}
	if !strings.Contains(got.Query, "fieldManager=certcenter") || !strings.Contains(got.Query, "force=true") {
		t.Errorf("query = %q, want a field manager and force", got.Query)
	}
	if got.Auth != "Bearer test-token" {
		t.Errorf("Authorization = %q", got.Auth)
	}

	if got.Body["type"] != "kubernetes.io/tls" {
		t.Errorf("type = %v, want kubernetes.io/tls", got.Body["type"])
	}
	data, _ := got.Body["data"].(map[string]any)
	crt, _ := base64.StdEncoding.DecodeString(data["tls.crt"].(string))
	key, _ := base64.StdEncoding.DecodeString(data["tls.key"].(string))
	// Ingress controllers expect the chain in tls.crt; the leaf alone
	// leaves clients to find the intermediates for themselves.
	if !strings.Contains(string(crt), "LEAF") || !strings.Contains(string(crt), "CHAIN") {
		t.Errorf("tls.crt = %q, want leaf and chain", crt)
	}
	if !strings.Contains(string(key), "KEY") {
		t.Errorf("tls.key = %q", key)
	}
}

func TestK8sSecretLeafOnly(t *testing.T) {
	srv, got := fakeAPIServer(t, http.StatusOK, `{}`)
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}

	cfg := k8sStepConfig(t, srv.URL, map[string]any{"leaf_only": true})
	if err := stepK8sSecret(context.Background(), st, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := got.Body["data"].(map[string]any)
	crt, _ := base64.StdEncoding.DecodeString(data["tls.crt"].(string))
	if strings.Contains(string(crt), "CHAIN") {
		t.Errorf("leaf_only still included the chain: %q", crt)
	}
}

func TestK8sSecretSurfacesTheAPIError(t *testing.T) {
	// The API's own message names the missing RBAC verb, which is the
	// usual cause and not something we could guess.
	srv, _ := fakeAPIServer(t, http.StatusForbidden,
		`{"message":"secrets is forbidden: User cannot patch resource \"secrets\""}`)
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}

	err := stepK8sSecret(context.Background(), st, k8sStepConfig(t, srv.URL, nil))
	if err == nil {
		t.Fatal("a 403 was accepted")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("error = %v, want the API's own message", err)
	}
}

func TestK8sSecretRequiresAName(t *testing.T) {
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}
	raw, _ := json.Marshal(map[string]any{"namespace": "web"})
	if err := stepK8sSecret(context.Background(), st, raw); err == nil {
		t.Error("a Secret with no name was accepted")
	}
}

func TestK8sOutsideAClusterWithoutCredentials(t *testing.T) {
	// Running outside a cluster with nothing configured has to explain
	// itself rather than failing on a missing file.
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}
	raw, _ := json.Marshal(map[string]any{"name": "x", "namespace": "web"})
	err := stepK8sSecret(context.Background(), st, raw)
	if err == nil {
		t.Fatal("no credentials were required")
	}
	if !strings.Contains(err.Error(), "inside a cluster") {
		t.Errorf("error = %v, want it to explain the in-cluster assumption", err)
	}
}

func TestK8sRestartStampsTheAnnotation(t *testing.T) {
	srv, got := fakeAPIServer(t, http.StatusOK, `{}`)
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}

	cfg := k8sStepConfig(t, srv.URL, map[string]any{"kind": "deployment", "name": "web"})
	if err := stepK8sRestart(context.Background(), st, cfg); err != nil {
		t.Fatalf("stepK8sRestart = %v", err)
	}
	if want := "/apis/apps/v1/namespaces/web/deployments/web"; got.Path != want {
		t.Errorf("path = %q, want %q", got.Path, want)
	}
	// A merge patch touches the annotation without claiming ownership of
	// the whole pod template, which an apply would.
	if !strings.Contains(got.ContentType, "strategic-merge-patch") {
		t.Errorf("Content-Type = %q", got.ContentType)
	}
	spec := got.Body["spec"].(map[string]any)
	tmpl := spec["template"].(map[string]any)
	meta := tmpl["metadata"].(map[string]any)
	ann := meta["annotations"].(map[string]any)
	if _, ok := ann["kubectl.kubernetes.io/restartedAt"]; !ok {
		t.Errorf("annotations = %v, want the same key kubectl rollout restart uses", ann)
	}
}

func TestK8sRestartKinds(t *testing.T) {
	srv, got := fakeAPIServer(t, http.StatusOK, `{}`)
	st := &pipelineState{cert: testCert(), paths: map[string]string{}}

	for kind, want := range map[string]string{
		"":            "deployments",
		"deployment":  "deployments",
		"statefulset": "statefulsets",
		"daemonset":   "daemonsets",
	} {
		cfg := k8sStepConfig(t, srv.URL, map[string]any{"kind": kind, "name": "w"})
		if err := stepK8sRestart(context.Background(), st, cfg); err != nil {
			t.Fatalf("kind %q: %v", kind, err)
		}
		if !strings.Contains(got.Path, "/"+want+"/") {
			t.Errorf("kind %q hit %q, want %s", kind, got.Path, want)
		}
	}

	cfg := k8sStepConfig(t, srv.URL, map[string]any{"kind": "cronjob", "name": "w"})
	if err := stepK8sRestart(context.Background(), st, cfg); err == nil {
		t.Error("an unsupported workload kind was accepted")
	}
}
