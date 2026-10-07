// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func probe(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/acme-directory", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestProbeDirectoryRequiresSession(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/acme-directory", `{"directoryUrl":"https://acme.example/dir"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestProbeDirectoryRejectsNonHTTPS(t *testing.T) {
	// The caller chooses the URL the server fetches, so the scheme is
	// pinned rather than left open.
	srv := newTestServer(t)
	for _, u := range []string{
		"http://acme.example/dir",
		"file:///etc/passwd",
		"ftp://acme.example/dir",
		"",
	} {
		rec := probe(t, srv, `{"directoryUrl":"`+u+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("probe(%q) status = %d, want 400", u, rec.Code)
		}
	}
}

func TestProbeDirectoryReportsUnreachableCA(t *testing.T) {
	srv := newTestServer(t)
	rec := probe(t, srv, `{"directoryUrl":"https://127.0.0.1:1/directory"}`)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var body apiError
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "CA_ERROR" {
		t.Errorf("code = %q, want CA_ERROR", body.Code)
	}
}
