// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
)

const testPassword = "correct horse battery"

// newTestServer builds a Server backed by an in-memory database with the
// admin password already seeded.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), db.SettingAdminPasswordHash, string(hash)); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Auth.SessionKey = string(testKey)
	cfg.Auth.Username = "admin"

	return &Server{
		DB:             store,
		Events:         NewBroker(),
		Sessions:       NewSessionManager(testKey, time.Hour),
		Config:         func() *config.Config { return cfg },
		AllowedOrigins: map[string]bool{"https://cc.example.com": true},
	}
}

func postJSON(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestLoginSuccessSetsCookie(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}
	var body struct {
		User string `json:"user"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.User != "admin" {
		t.Errorf("user = %q, want admin", body.User)
	}

	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatal("no session cookie set")
	}
	if !found.HttpOnly {
		t.Error("cookie is not HttpOnly — a XSS could then read the session")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", found.SameSite)
	}
	if _, err := srv.Sessions.Verify(found.Value, time.Now()); err != nil {
		t.Errorf("cookie value does not verify: %v", err)
	}
}

func TestLoginFailures(t *testing.T) {
	tests := []struct {
		name, body string
		wantStatus int
		wantCode   string
	}{
		{"密码错误", `{"username":"admin","password":"nope"}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"用户名错误", `{"username":"root","password":"` + testPassword + `"}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"空密码", `{"username":"admin","password":""}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"请求体不是 JSON", `not json`, http.StatusBadRequest, "BAD_REQUEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			rec := postJSON(t, srv, "/api/auth/login", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			var body apiError
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", body.Code, tt.wantCode)
			}
			if strings.Contains(strings.ToLower(body.Message), testPassword) {
				t.Error("error message leaks the password")
			}
		})
	}
}

func TestProtectedRouteRequiresSession(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without a session = %d, want 401", rec.Code)
	}

	tok, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cookie 认证", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
		}
		var body struct {
			User string `json:"user"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.User != "admin" {
			t.Errorf("user = %q, want admin", body.User)
		}
	})

	t.Run("Bearer 认证", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("伪造令牌", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer bogus.sig")
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestLogoutClearsCookie(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/auth/logout", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			if c.MaxAge >= 0 {
				t.Errorf("MaxAge = %d, want negative so the browser drops it", c.MaxAge)
			}
			return
		}
	}
	t.Error("logout did not send a clearing cookie")
}

func TestOriginGuard(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		name, method, origin string
		wantBlocked          bool
	}{
		{"允许的来源可写", http.MethodPost, "https://cc.example.com", false},
		{"陌生来源被拒", http.MethodPost, "https://evil.example.com", true},
		{"无 Origin 头放行（curl/脚本）", http.MethodPost, "", false},
		{"GET 不受限", http.MethodGet, "https://evil.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/auth/login", strings.NewReader(`{}`))
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)

			blocked := rec.Code == http.StatusForbidden
			if blocked != tt.wantBlocked {
				t.Errorf("blocked = %v (status %d), want %v", blocked, rec.Code, tt.wantBlocked)
			}
		})
	}
}

func TestOriginGuardDisabledWhenNoOriginsConfigured(t *testing.T) {
	// 单域名部署在反向代理后面时不配 external-url，此时不应拦任何来源，
	// 否则服务直接不可用。
	srv := newTestServer(t)
	srv.AllowedOrigins = nil

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://anything.example.com")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Error("status = 403 with no configured origins, want the guard disabled")
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	srv := newTestServer(t)
	huge := `{"username":"admin","password":"` + strings.Repeat("x", maxRequestBody+1) + `"}`
	rec := postJSON(t, srv, "/api/auth/login", huge)
	if rec.Code == http.StatusOK {
		t.Fatalf("status = 200, want a rejection for an oversized body")
	}
}
