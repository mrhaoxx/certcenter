// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeHealthAgainstAServer(t *testing.T) {
	// The runtime image is distroless — no shell, no curl — so a container
	// health check has to be the binary probing itself.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	if code := probeHealth("", addr); code != 0 {
		t.Errorf("probeHealth against a healthy server = %d, want 0", code)
	}
}

func TestProbeHealthFailures(t *testing.T) {
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	tests := []struct{ name, addr string }{
		{"服务不健康", strings.TrimPrefix(unhealthy.URL, "http://")},
		{"端口无人监听", "127.0.0.1:1"},
		{"地址不合法", "not-an-address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code := probeHealth("", tt.addr); code == 0 {
				t.Errorf("probeHealth(%q) = 0, want a non-zero exit", tt.addr)
			}
		})
	}
}

func TestProbeHealthRewritesWildcardAddress(t *testing.T) {
	// The configured address is where the server listens, not somewhere a
	// client can connect: dialling 0.0.0.0 fails on some platforms and is
	// meaningless on all of them.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	if code := probeHealth("", "0.0.0.0:"+port); code != 0 {
		t.Errorf("probeHealth on 0.0.0.0 = %d, want it rewritten to loopback", code)
	}
}
