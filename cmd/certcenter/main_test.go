// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestOriginOf(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://cc.example.com", "https://cc.example.com"},
		{"https://cc.example.com/", "https://cc.example.com"},
		{"https://cc.example.com/ui/index.html", "https://cc.example.com"},
		{"http://localhost:3001/x", "http://localhost:3001"},
		{"", ""},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := originOf(tt.in); got != tt.want {
			t.Errorf("originOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitNonEmpty(t *testing.T) {
	got := splitNonEmpty(" a , ,b,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitNonEmpty = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitNonEmpty = %v, want %v", got, want)
		}
	}
}

func TestSplitListen(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{"127.0.0.1:8080", "127.0.0.1", 8080, false},
		{":3001", "0.0.0.0", 3001, false},
		{"nocolon", "", 0, true},
		{"host:notaport", "", 0, true},
		{"host:0", "", 0, true},
	}
	for _, tt := range tests {
		host, port, err := splitListen(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitListen(%q) = nil error, want failure", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitListen(%q) = %v", tt.in, err)
			continue
		}
		if host != tt.wantHost || port != tt.wantPort {
			t.Errorf("splitListen(%q) = %q, %d; want %q, %d", tt.in, host, port, tt.wantHost, tt.wantPort)
		}
	}
}
