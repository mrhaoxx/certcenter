// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestIssueThenVerify(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	now := time.Unix(1_700_000_000, 0)

	tok, err := m.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := m.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q, want %q", sess.User, "admin")
	}
	if !sess.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("Expires = %v, want %v", sess.Expires, now.Add(time.Hour))
	}
}

func TestVerifyRejects(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	valid, err := m.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}

	// 换一把密钥签的同一份载荷必须被拒——这是防伪造的核心。
	other := NewSessionManager([]byte("ffffffffffffffffffffffffffffffff"), time.Hour)
	forged, err := other.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		token string
		when  time.Time
	}{
		{"空令牌", "", now},
		{"缺分隔符", "garbage", now},
		{"签名被篡改", valid[:len(valid)-4] + "AAAA", now},
		{"载荷被篡改", strings.Replace(valid, "a", "b", 1), now},
		{"用别的密钥签的", forged, now},
		{"已过期", valid, now.Add(2 * time.Hour)},
		{"刚好到期", valid, now.Add(time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := m.Verify(tt.token, tt.when); err == nil {
				t.Error("Verify() = nil error, want rejection")
			}
		})
	}
}

func TestIssueRejectsEmptyUser(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	if _, err := m.Issue("", time.Now()); err == nil {
		t.Error("Issue(\"\") = nil error, want rejection")
	}
}

func TestUserWithSeparatorIsRejected(t *testing.T) {
	// 载荷用 "|" 分隔字段；用户名里带 "|" 会让解析产生歧义，
	// 必须在签发时就拒绝，而不是留到验证时才发现。
	m := NewSessionManager(testKey, time.Hour)
	if _, err := m.Issue("ad|min", time.Now()); err == nil {
		t.Error("Issue with a separator in the user = nil error, want rejection")
	}
}

func TestTTLIsExposed(t *testing.T) {
	m := NewSessionManager(testKey, 3*time.Hour)
	if got := m.TTL(); got != 3*time.Hour {
		t.Errorf("TTL() = %v, want 3h", got)
	}
}
