// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestDNSSettingsFallBackToConfig(t *testing.T) {
	// Nothing stored yet: the values come from config.toml, so the UI shows
	// what the service is actually using rather than a blank form.
	srv := newTestServer(t)
	rec := authed(t, srv, http.MethodGet, "/api/settings/dns", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got db.DNSSettings
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Server == "" {
		t.Error("server is empty; the configured default should show through")
	}
	if got.Retries <= 0 {
		t.Errorf("retries = %d, want the configured default", got.Retries)
	}
}

func TestDNSSettingsRoundTrip(t *testing.T) {
	srv := newTestServer(t)
	body := `{"server":"https://dns.alidns.com/resolve","retries":3,"skip":true}`
	if rec := authed(t, srv, http.MethodPut, "/api/settings/dns", body); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200, body = %s", rec.Code, rec.Body)
	}

	rec := authed(t, srv, http.MethodGet, "/api/settings/dns", "")
	var got db.DNSSettings
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Server != "https://dns.alidns.com/resolve" || got.Retries != 3 || !got.Skip {
		t.Errorf("settings = %+v, want the stored values", got)
	}
}

func TestDNSSettingsValidation(t *testing.T) {
	tests := []struct{ name, body string }{
		{"明文 http 的解析器", `{"server":"http://dns.example/q","retries":3,"skip":false}`},
		{"空地址", `{"server":"","retries":3,"skip":false}`},
		{"重试次数为 0", `{"server":"https://d.example/q","retries":0,"skip":false}`},
		{"重试次数过大", `{"server":"https://d.example/q","retries":999,"skip":false}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			rec := authed(t, srv, http.MethodPut, "/api/settings/dns", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestDNSSettingsRequireSession(t *testing.T) {
	srv := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings/dns", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
