// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestBackupRequiresSession(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/backup", `{"passphrase":"a long enough one"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — a backup is every secret the service holds", rec.Code)
	}
}

func TestBackupRejectsWeakPassphrase(t *testing.T) {
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/backup", strings.NewReader(`{"passphrase":"short"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body apiError
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Code != "BAD_REQUEST" {
		t.Errorf("code = %q", body.Code)
	}
}

func TestBackupDownloadDecrypts(t *testing.T) {
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	const pass = "a sufficiently long passphrase"

	req := httptest.NewRequest(http.MethodPost, "/api/backup",
		strings.NewReader(`{"passphrase":"`+pass+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}
	disposition := rec.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, ".tar.gz.age") {
		t.Errorf("Content-Disposition = %q, want a .tar.gz.age filename", disposition)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response is cacheable; it contains private keys")
	}

	// The bytes must be a real age file, not an error page.
	identity, err := age.NewScryptIdentity(pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(bytes.NewReader(rec.Body.Bytes()), identity); err != nil {
		t.Fatalf("the downloaded body does not decrypt: %v", err)
	}

	// And it must be audited: an export of every secret is worth a log line.
	logs, err := srv.DB.ListLogs(req.Context(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range logs {
		if l.Action == "backup" {
			found = true
		}
	}
	if !found {
		t.Errorf("no backup entry in the operation log; got %+v", logs)
	}
}
