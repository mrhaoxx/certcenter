// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAliyunCanHandle(t *testing.T) {
	p, err := New(KindAliyun, `{"access_key_id":"k","access_key_secret":"s","domain":"example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		fqdn string
		want bool
	}{
		{"_acme-challenge.example.com", true},
		{"example.com", true},
		{"deep.sub.example.com", true},
		{"_acme-challenge.example.net", false},
		{"notexample.com", false},
	}
	for _, tt := range tests {
		got, err := p.CanHandle(context.Background(), tt.fqdn)
		if err != nil {
			t.Errorf("CanHandle(%q) errored: %v", tt.fqdn, err)
		}
		if got != tt.want {
			t.Errorf("CanHandle(%q) = %v, want %v", tt.fqdn, got, tt.want)
		}
	}
}

func TestCloudflareCanHandleDiscovers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "example.com" {
			w.Write([]byte(`{"success":true,"result":[{"id":"zone1","name":"example.com"}]}`))
			return
		}
		w.Write([]byte(`{"success":true,"result":[]}`))
	}))
	defer srv.Close()

	p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
	for _, tt := range []struct {
		fqdn string
		want bool
	}{
		{"_acme-challenge.example.com", true},
		{"_acme-challenge.other.net", false},
	} {
		got, err := p.CanHandle(context.Background(), tt.fqdn)
		if err != nil {
			t.Errorf("CanHandle(%q) errored: %v", tt.fqdn, err)
		}
		if got != tt.want {
			t.Errorf("CanHandle(%q) = %v, want %v", tt.fqdn, got, tt.want)
		}
	}
}

func TestCloudflareCanHandleWithPinnedZone(t *testing.T) {
	// An operator who set zone_id has already said which zone to use, so
	// there is nothing to discover and no API call to make.
	p := &cloudflare{token: "t", zoneID: "z1", baseURL: "https://unreachable.invalid"}
	got, err := p.CanHandle(context.Background(), "_acme-challenge.anything.example")
	if err != nil {
		t.Fatalf("CanHandle errored despite a pinned zone: %v", err)
	}
	if !got {
		t.Error("CanHandle = false with zone_id pinned")
	}
}

func TestCloudflareCanHandleReportsAnUnreachableAPI(t *testing.T) {
	// The distinction that matters: an API that cannot answer must not look
	// like an account that does not own the domain, or the record gets
	// routed to the wrong provider and the error blames the wrong thing.
	p := &cloudflare{token: "t", baseURL: "http://127.0.0.1:1", discovered: map[string]string{}}
	got, err := p.CanHandle(context.Background(), "_acme-challenge.example.com")
	if err == nil {
		t.Fatal("an unreachable API reported a definite answer")
	}
	if got {
		t.Error("CanHandle = true despite the error")
	}
}

func TestCloudflareCanHandlePermissionErrorIsNotADenial(t *testing.T) {
	// A token without Zone:Read cannot list zones. That is an unanswerable
	// question, not proof the domain belongs elsewhere.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`))
	}))
	defer srv.Close()

	p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
	if _, err := p.CanHandle(context.Background(), "_acme-challenge.example.com"); err == nil {
		t.Error("a permission failure was reported as 'not my zone'")
	}
}
