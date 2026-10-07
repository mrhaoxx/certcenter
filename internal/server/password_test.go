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

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestSeedAdminPassword(t *testing.T) {
	ctx := context.Background()

	newStore := func(t *testing.T) *db.SQLite {
		t.Helper()
		s, err := db.OpenMemory()
		if err != nil {
			t.Fatalf("open test database: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}

	t.Run("空库时播种", func(t *testing.T) {
		store := newStore(t)
		if err := SeedAdminPassword(ctx, store, "$2a$12$fromconfig"); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetSetting(ctx, db.SettingAdminPasswordHash)
		if err != nil {
			t.Fatal(err)
		}
		if got != "$2a$12$fromconfig" {
			t.Errorf("hash = %q, want the config value", got)
		}
	})

	t.Run("已有值时不覆盖", func(t *testing.T) {
		// 这是本任务的核心保证：改过密码后重启，配置文件里的旧
		// 散列不能把用户的新密码顶掉。
		store := newStore(t)
		if err := store.SetSetting(ctx, db.SettingAdminPasswordHash, "$2a$12$changedbyuser"); err != nil {
			t.Fatal(err)
		}
		if err := SeedAdminPassword(ctx, store, "$2a$12$fromconfig"); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetSetting(ctx, db.SettingAdminPasswordHash)
		if err != nil {
			t.Fatal(err)
		}
		if got != "$2a$12$changedbyuser" {
			t.Errorf("hash = %q, want the stored value to survive", got)
		}
	})

	t.Run("配置里也没有散列时报错", func(t *testing.T) {
		store := newStore(t)
		if err := SeedAdminPassword(ctx, store, ""); err == nil {
			t.Error("SeedAdminPassword with an empty hash = nil, want an error")
		}
	})
}

func putJSON(t *testing.T, srv *Server, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestChangePassword(t *testing.T) {
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rec := putJSON(t, srv, "/api/me/password",
		`{"oldPassword":"`+testPassword+`","newPassword":"a-brand-new-secret"}`, token)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body)
	}

	// 新密码可用。
	hash, err := srv.DB.GetSetting(context.Background(), db.SettingAdminPasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-brand-new-secret")) != nil {
		t.Error("the new password does not verify against the stored hash")
	}
	// 旧密码失效。
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testPassword)) == nil {
		t.Error("the old password still verifies")
	}

	// 审计留痕。
	logs, err := srv.DB.ListLogs(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Action != "change_password" {
		t.Errorf("logs = %+v, want one change_password entry", logs)
	}
}

func TestChangePasswordThenLoginWithIt(t *testing.T) {
	// 端到端闭环：改完密码必须能立刻用新密码登录，不需要重启。
	// 这正是 Rust 实现做不到的——它改的是 config.toml 的字符串，
	// 内存里的配置不变。
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec := putJSON(t, srv, "/api/me/password",
		`{"oldPassword":"`+testPassword+`","newPassword":"the-new-one"}`, token); rec.Code != http.StatusNoContent {
		t.Fatalf("change status = %d, want 204", rec.Code)
	}

	if rec := postJSON(t, srv, "/api/auth/login",
		`{"username":"admin","password":"the-new-one"}`); rec.Code != http.StatusOK {
		t.Errorf("login with the new password = %d, want 200", rec.Code)
	}
	if rec := postJSON(t, srv, "/api/auth/login",
		`{"username":"admin","password":"`+testPassword+`"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("login with the old password = %d, want 401", rec.Code)
	}
}

func TestChangePasswordRejections(t *testing.T) {
	tests := []struct {
		name, body  string
		withSession bool
		wantStatus  int
		wantCode    string
	}{
		{"未登录", `{"oldPassword":"x","newPassword":"yyyyyyyy"}`, false, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"旧密码错误", `{"oldPassword":"wrong","newPassword":"yyyyyyyy"}`, true, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"新密码太短", `{"oldPassword":"` + testPassword + `","newPassword":"short"}`, true, http.StatusBadRequest, "BAD_REQUEST"},
		{"请求体不是 JSON", `nope`, true, http.StatusBadRequest, "BAD_REQUEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			token := ""
			if tt.withSession {
				var err error
				token, err = srv.Sessions.Issue("admin", time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			rec := putJSON(t, srv, "/api/me/password", tt.body, token)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tt.wantStatus, rec.Body)
			}
			var body apiError
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", body.Code, tt.wantCode)
			}

			// 失败时存储的散列不能变。
			hash, err := srv.DB.GetSetting(context.Background(), db.SettingAdminPasswordHash)
			if err != nil {
				t.Fatal(err)
			}
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testPassword)) != nil {
				t.Error("a failed change modified the stored password")
			}
		})
	}
}
