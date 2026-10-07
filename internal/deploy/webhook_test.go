// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookDeploy(t *testing.T) {
	var gotBody, gotAuth, gotContentType string
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	target, err := newWebhook(`{"url":"` + srv.URL + `","headers":{"Authorization":"Bearer tok"}}`)
	if err != nil {
		t.Fatal(err)
	}
	events, err := target.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy() = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want the configured header", gotAuth)
	}

	// 字段名是数据契约，现有接收方按这些名字解析。
	var payload map[string]string
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	for k, want := range map[string]string{
		"domain":      "example.com",
		"certificate": "LEAF-PEM\n",
		"private_key": "KEY-PEM\n",
		"chain":       "CHAIN-PEM\n",
	} {
		if payload[k] != want {
			t.Errorf("payload[%q] = %q, want %q", k, payload[k], want)
		}
	}
	if !hasEvent(events, "webhook_response", "202") {
		t.Errorf("events = %v, want the response recorded", eventSummary(events))
	}
}

func TestWebhookNonZeroStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("upstream exploded"))
	}))
	defer srv.Close()

	target, _ := newWebhook(`{"url":"` + srv.URL + `"}`)
	events, err := target.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want a 500 to fail the deployment")
	}
	if !hasEvent(events, "webhook_response", "upstream exploded") {
		t.Errorf("events = %v, want the response body in the detail", eventSummary(events))
	}
}

func TestWebhookTransportErrorReturnsEvents(t *testing.T) {
	// 失败也要带回事件——这正是操作者排查时要看的。
	target, _ := newWebhook(`{"url":"http://127.0.0.1:1/nope"}`)
	events, err := target.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want a transport failure")
	}
	if len(events) == 0 {
		t.Error("no events returned on the failure path")
	}
	if !hasEvent(events, "webhook_error", "failed") {
		t.Errorf("events = %v, want the transport error recorded", eventSummary(events))
	}
}

func TestWebhookRequiresURL(t *testing.T) {
	if _, err := newWebhook(`{}`); err == nil {
		t.Error("newWebhook without a url = nil error, want failure")
	}
}

func TestNewRejectsUnknownKind(t *testing.T) {
	if _, err := New("carrier_pigeon", `{}`, Options{}); err == nil {
		t.Error("New with an unknown kind = nil error, want failure")
	}
}

func TestPipelineIsTheOnlyKind(t *testing.T) {
	// Five kinds meant a target could do exactly one thing. What each of
	// them did is a step now.
	kinds := Kinds()
	if len(kinds) != 1 || kinds[0] != KindPipeline {
		t.Errorf("Kinds() = %v, want just %q", kinds, KindPipeline)
	}
}

func TestOldKindNamesExplainTheChange(t *testing.T) {
	// Anyone with a stored target or a script using the old names should
	// be told where the behaviour went, not just refused.
	for _, old := range []string{"ssh", "webhook", "configcenter", "aliyun_cdn", "tencent_cdn"} {
		_, err := New(old, `{}`, Options{})
		if err == nil {
			t.Errorf("New(%q) = nil error, want a refusal", old)
			continue
		}
		if !strings.Contains(err.Error(), "step") {
			t.Errorf("New(%q) error = %v, want it to point at steps", old, err)
		}
	}
}

func TestFullChainPEM(t *testing.T) {
	tests := []struct {
		name        string
		cert, chain string
		want        string
	}{
		{"叶子与链拼接", "LEAF\n", "INTER\n", "LEAF\nINTER\n"},
		{"叶子缺尾换行也能拼", "LEAF", "INTER\n", "LEAF\nINTER\n"},
		{"无中间证书时就是叶子", "LEAF\n", "", "LEAF\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CertificateData{CertPEM: tt.cert, ChainPEM: tt.chain}
			if got := c.FullChainPEM(); got != tt.want {
				t.Errorf("FullChainPEM() = %q, want %q", got, tt.want)
			}
		})
	}
}
