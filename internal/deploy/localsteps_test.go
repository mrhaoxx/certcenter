// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newState(t *testing.T) *pipelineState {
	t.Helper()
	return &pipelineState{cert: testCert(), paths: map[string]string{}}
}

func TestLocalWriteWritesEachMaterial(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		source, want string
		pathKey      string
	}{
		{SourceCertificate, "LEAF", "cert_path"},
		{SourcePrivateKey, "KEY", "key_path"},
		{SourceChain, "CHAIN", "chain_path"},
		{SourceFullChain, "LEAF", "fullchain_path"},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			st := newState(t)
			path := filepath.Join(dir, tt.source+".pem")
			cfg, _ := json.Marshal(map[string]any{"source": tt.source, "path": path})

			if err := stepLocalWrite(context.Background(), st, cfg); err != nil {
				t.Fatalf("stepLocalWrite = %v", err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), tt.want) {
				t.Errorf("file holds %q, want it to contain %q", body, tt.want)
			}
			// Later steps reference the written path by placeholder.
			if st.paths[tt.pathKey] != path {
				t.Errorf("%s = %q, want %q", tt.pathKey, st.paths[tt.pathKey], path)
			}
		})
	}
}

func TestLocalWriteAppliesMode(t *testing.T) {
	// A private key readable by everything on the box is the kind of thing
	// nobody notices until an audit.
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	cfg, _ := json.Marshal(map[string]any{
		"source": SourcePrivateKey, "path": path, "mode": "0600",
	})
	if err := stepLocalWrite(context.Background(), newState(t), cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

func TestLocalWriteReplacesAtomically(t *testing.T) {
	// A reader that opens the file partway through a plain write gets a
	// truncated certificate, and a server reloading at that moment fails
	// to start. Writing to a temporary file and renaming avoids the window.
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("OLD CONTENT"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _ := json.Marshal(map[string]any{"source": SourceCertificate, "path": path})
	if err := stepLocalWrite(context.Background(), newState(t), cfg); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "OLD") {
		t.Error("the old content survived")
	}
	// No temporary files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".certcenter-") {
			t.Errorf("a temporary file was left behind: %s", e.Name())
		}
	}
}

func TestLocalWriteEnsureDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deep", "cert.pem")

	cfg, _ := json.Marshal(map[string]any{"source": SourceCertificate, "path": path})
	if err := stepLocalWrite(context.Background(), newState(t), cfg); err == nil {
		t.Error("writing into a missing directory succeeded without ensure_dir")
	}

	cfg, _ = json.Marshal(map[string]any{
		"source": SourceCertificate, "path": path, "ensure_dir": true,
	})
	if err := stepLocalWrite(context.Background(), newState(t), cfg); err != nil {
		t.Fatalf("ensure_dir did not create the parent: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error(err)
	}
}

func TestLocalWriteRendersContent(t *testing.T) {
	// The rendered form is how an nginx snippet naming both files gets
	// written in one step.
	dir := t.TempDir()
	path := filepath.Join(dir, "snippet.conf")
	cfg, _ := json.Marshal(map[string]any{
		"path":    path,
		"content": "ssl_certificate_key_data {{domain}};",
	})
	if err := stepLocalWrite(context.Background(), newState(t), cfg); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "example.com") {
		t.Errorf("placeholders were not expanded: %s", body)
	}
}

func TestLocalWriteRejectsBadInput(t *testing.T) {
	for _, cfg := range []map[string]any{
		{"source": SourceCertificate},            // no path
		{"source": "nonsense", "path": "/tmp/x"}, // unknown source
	} {
		raw, _ := json.Marshal(cfg)
		if err := stepLocalWrite(context.Background(), newState(t), raw); err == nil {
			t.Errorf("stepLocalWrite(%v) = nil error, want failure", cfg)
		}
	}
}

func TestHTTPRequestInsecureSkipsVerification(t *testing.T) {
	// A reload endpoint often runs on the host being re-certified and
	// presents the old or a self-signed certificate exactly when this step
	// fires; verifying it would fail when the step matters most.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	strict, _ := json.Marshal(map[string]any{"url": srv.URL})
	if err := stepHTTPRequest(context.Background(), newState(t), strict); err == nil {
		t.Error("the self-signed endpoint was accepted without insecure")
	}

	relaxed, _ := json.Marshal(map[string]any{"url": srv.URL, "insecure": true})
	if err := stepHTTPRequest(context.Background(), newState(t), relaxed); err != nil {
		t.Errorf("insecure did not skip verification: %v", err)
	}
}

func TestHTTPRequestExpectStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	// Without an expectation a bad status is a note, matching run_command.
	quiet, _ := json.Marshal(map[string]any{"url": srv.URL})
	if err := stepHTTPRequest(context.Background(), newState(t), quiet); err != nil {
		t.Errorf("an unexpected status was fatal without expect_status: %v", err)
	}

	// With one, "the reload returned 500" stops the pipeline.
	strict, _ := json.Marshal(map[string]any{"url": srv.URL, "expect_status": 200})
	err := stepHTTPRequest(context.Background(), newState(t), strict)
	if err == nil {
		t.Fatal("expect_status did not fail the step")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "200") {
		t.Errorf("error = %v, want both the actual and expected status", err)
	}
}

func TestInsecureClientIsSeparate(t *testing.T) {
	// The relaxed transport must not become the default for every step.
	if httpClient.Transport != nil {
		if tr, ok := httpClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
			if tr.TLSClientConfig.InsecureSkipVerify {
				t.Error("the shared client skips verification")
			}
		}
	}
	tr, ok := insecureHTTPClient.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("the insecure client does not actually skip verification")
	}
	var _ = tls.Config{}
}
