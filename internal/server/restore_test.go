// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// uploadArchive posts a multipart restore request.
func uploadArchive(t *testing.T, srv *Server, body []byte, passphrase string, authed bool) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if passphrase != "" {
		_ = mw.WriteField("passphrase", passphrase)
	}
	part, err := mw.CreateFormFile("archive", "backup.tar.gz.age")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatal(err)
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/backup/restore", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if authed {
		token, err := srv.Sessions.Issue("admin", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

// exportedArchive downloads a backup of the given server.
func exportedArchive(t *testing.T, srv *Server, passphrase string) []byte {
	t.Helper()
	rec := authed(t, srv, http.MethodPost, "/api/backup", `{"passphrase":"`+passphrase+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status = %d", rec.Code)
	}
	return rec.Body.Bytes()
}

func TestRestoreRoundTripThroughTheAPI(t *testing.T) {
	const pass = "a sufficiently long passphrase"

	// A server holding something distinctive, exported.
	source, _ := newServerWithIssuedCertificate(t)
	if _, err := source.DB.CreateDNSProvider(context.Background(), db.DNSProvider{
		Name: "from-backup", Kind: "cloudflare", Config: `{"api_token":"restored-token","zone_id":"z"}`,
	}); err != nil {
		t.Fatal(err)
	}
	archive := exportedArchive(t, source, pass)

	// A different server, with data of its own that must go.
	target := newTestServer(t)
	if _, err := target.DB.CreateDNSProvider(context.Background(), db.DNSProvider{
		Name: "stale", Kind: "cloudflare", Config: `{"api_token":"old","zone_id":"z"}`,
	}); err != nil {
		t.Fatal(err)
	}

	rec := uploadArchive(t, target, archive, pass, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
	var report struct {
		Rows map[string]int `json:"rows"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.Rows["certificates"] == 0 {
		t.Errorf("rows = %v, want the certificate restored", report.Rows)
	}

	providers, err := target.DB.ListDNSProviders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, p := range providers {
		names[p.Name] = p.Config
	}
	if _, stillThere := names["stale"]; stillThere {
		t.Error("the target's own provider survived the restore")
	}
	config, restored := names["from-backup"]
	if !restored {
		t.Fatalf("providers = %v, want the archive's", names)
	}
	// The credential has to survive, or the restore was cosmetic.
	if !strings.Contains(config, "restored-token") {
		t.Errorf("config = %q, want the archive's token", config)
	}
}

func TestRestoreRequiresSession(t *testing.T) {
	// A restore replaces every credential the service holds.
	srv := newTestServer(t)
	rec := uploadArchive(t, srv, []byte("whatever"), "pass", false)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRestoreRejectionLeavesDataIntact(t *testing.T) {
	// The failure that matters: an operator uploads the wrong file, and
	// the service must still be holding its data afterwards.
	srv := newTestServer(t)
	if _, err := srv.DB.CreateDNSProvider(context.Background(), db.DNSProvider{
		Name: "live", Kind: "cloudflare", Config: `{"api_token":"keep-me","zone_id":"z"}`,
	}); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct{ name, body, pass string }{
		{"不是归档文件", "just some bytes", "a sufficiently long passphrase"},
		{"口令错误", "", "wrong passphrase entirely"},
		{"缺口令", "x", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.body)
			if tt.body == "" {
				body = exportedArchive(t, srv, "a sufficiently long passphrase")
			}
			rec := uploadArchive(t, srv, body, tt.pass, true)
			if rec.Code == http.StatusOK {
				t.Fatalf("status = 200, want a rejection")
			}
			providers, err := srv.DB.ListDNSProviders(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(providers) != 1 || !strings.Contains(providers[0].Config, "keep-me") {
				t.Errorf("live data was damaged by a rejected restore: %+v", providers)
			}
		})
	}
}
