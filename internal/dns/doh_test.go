// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifierLookupMatches(t *testing.T) {
	var gotName, gotType, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotName = r.URL.Query().Get("name")
		gotType = r.URL.Query().Get("type")
		gotAccept = r.Header.Get("Accept")
		w.Write([]byte(`{"Status":0,"Answer":[{"name":"_acme-challenge.example.com","type":16,"data":"\"the-digest\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 1, time.Millisecond)
	ok, err := v.lookup(context.Background(), "_acme-challenge.example.com", "the-digest")
	if err != nil {
		t.Fatalf("lookup() = %v", err)
	}
	if !ok {
		t.Error("lookup() = false, want true")
	}
	if gotName != "_acme-challenge.example.com" {
		t.Errorf("name = %q", gotName)
	}
	if gotType != "TXT" {
		t.Errorf("type = %q, want TXT", gotType)
	}
	if gotAccept != "application/dns-json" {
		t.Errorf("Accept = %q, want application/dns-json", gotAccept)
	}
}

func TestVerifierLookupStripsQuotes(t *testing.T) {
	tests := []struct {
		name, data, want string
		match            bool
	}{
		{"带引号", `"digest"`, "digest", true},
		{"不带引号", `digest`, "digest", true},
		{"值不同", `"other"`, "digest", false},
		{"多段拼接的长 TXT", `"part-one" "part-two"`, "part-onepart-two", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"Status":0,"Answer":[{"data":` + jsonQuote(tt.data) + `}]}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			}))
			defer srv.Close()

			v := NewVerifier(srv.URL, 1, time.Millisecond)
			ok, err := v.lookup(context.Background(), "n", tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tt.match {
				t.Errorf("lookup() = %v, want %v (data %q, expected %q)", ok, tt.match, tt.data, tt.want)
			}
		})
	}
}

func TestVerifierNXDOMAINIsNotAnError(t *testing.T) {
	// 记录刚建好、还没传播时权威服务器会回 NXDOMAIN。这是"再等等"，
	// 不是错误——当成错误会让签发在第一次查询就失败。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":3}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 1, time.Millisecond)
	ok, err := v.lookup(context.Background(), "n", "v")
	if err != nil {
		t.Errorf("lookup() on NXDOMAIN = %v, want nil error", err)
	}
	if ok {
		t.Error("lookup() = true on NXDOMAIN, want false")
	}
}

func TestVerifierWaitRetriesUntilVisible(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Write([]byte(`{"Status":0,"Answer":[]}`))
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 5, time.Millisecond)
	if err := v.Wait(context.Background(), "n", "v"); err != nil {
		t.Fatalf("Wait() = %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("queries = %d, want 3 (stops as soon as the record is visible)", got)
	}
}

func TestVerifierWaitExhaustsRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"Status":0,"Answer":[]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 3, time.Millisecond)
	err := v.Wait(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("Wait() = nil error, want a timeout after the retries run out")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("queries = %d, want exactly 3", got)
	}
}

func TestVerifierWaitHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":0,"Answer":[]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := NewVerifier(srv.URL, 100, time.Hour)
	start := time.Now()
	if err := v.Wait(ctx, "n", "v"); err == nil {
		t.Error("Wait() with a cancelled context = nil error, want failure")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Wait() took %v; a cancelled context must not sleep through the interval", elapsed)
	}
}

func TestVerifierTransportErrorCountsAsRetry(t *testing.T) {
	// DoH 服务器抖动不应直接判定签发失败，只算一次失败尝试。
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 4, time.Millisecond)
	if err := v.Wait(context.Background(), "n", "v"); err != nil {
		t.Errorf("Wait() = %v, want it to ride out a transient 502", err)
	}
}

func TestNewVerifierDefaults(t *testing.T) {
	v := NewVerifier("", 0, 0)
	if v.Server != DefaultDoHServer {
		t.Errorf("Server = %q, want %q", v.Server, DefaultDoHServer)
	}
	if v.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", v.MaxRetries, DefaultMaxRetries)
	}
	if v.Interval != DefaultInterval {
		t.Errorf("Interval = %v, want %v", v.Interval, DefaultInterval)
	}
	if v.client == nil || v.client.Timeout == 0 {
		t.Error("the DoH client must have a timeout; the Rust implementation had none")
	}
}

// jsonQuote 把字符串编码成 JSON 字面量，供表驱动构造响应体。
func jsonQuote(s string) string {
	var b []byte
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b = append(b, '\\')
		}
		b = append(b, s[i])
	}
	return string(append(b, '"'))
}
