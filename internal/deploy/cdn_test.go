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
	"time"
)

func TestAliyunCDNDeploy(t *testing.T) {
	var gotQuery, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{"RequestId":"abc"}`))
	}))
	defer srv.Close()

	target, err := newAliyunCDN(`{"access_key_id":"k","access_key_secret":"s","cdn_domain":"cdn.example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	a := target.(*aliyunCDN)
	a.endpoint = srv.URL
	a.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	a.nonce = func() string { return "fixed" }

	events, err := a.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy() = %v", err)
	}

	if !strings.Contains(gotAuth, "ACS3-HMAC-SHA256 Credential=k,") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	// 参数按 key 排序、空格编成 %20，与签名的查询串一致。
	if strings.Contains(gotQuery, "+") {
		t.Errorf("query %q contains '+', the signature would not verify", gotQuery)
	}
	for _, want := range []string{"DomainName=cdn.example.com", "CertType=upload", "SSLProtocol=on"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query = %q, want it to contain %q", gotQuery, want)
		}
	}
	if !hasEvent(events, "aliyun_cdn", "installed") {
		t.Errorf("events = %v", eventSummary(events))
	}
}

func TestAliyunCDNSendsFullChain(t *testing.T) {
	// CDN 要的是完整链；库里叶子和中间证书是分开存的，这里必须重新拼。
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte(`{"RequestId":"abc"}`))
	}))
	defer srv.Close()

	target, _ := newAliyunCDN(`{"access_key_id":"k","access_key_secret":"s","cdn_domain":"c.example.com"}`)
	a := target.(*aliyunCDN)
	a.endpoint = srv.URL

	if _, err := a.Deploy(context.Background(), testCert()); err != nil {
		t.Fatal(err)
	}
	// LEAF-PEM 与 CHAIN-PEM 都要出现在 SSLPub 里（URL 编码后）。
	for _, want := range []string{"LEAF-PEM", "CHAIN-PEM"} {
		if !strings.Contains(gotQuery, want) {
			t.Errorf("query does not carry %q; SSLPub must be the full chain", want)
		}
	}
}

func TestAliyunCDNSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"Code":"InvalidDomain.NotFound","Message":"domain not found"}`))
	}))
	defer srv.Close()

	target, _ := newAliyunCDN(`{"access_key_id":"k","access_key_secret":"s","cdn_domain":"x"}`)
	a := target.(*aliyunCDN)
	a.endpoint = srv.URL

	events, err := a.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want the API error surfaced")
	}
	if !strings.Contains(err.Error(), "InvalidDomain.NotFound") {
		t.Errorf("error = %v, want the API Code", err)
	}
	if !hasEvent(events, "aliyun_cdn", "domain not found") {
		t.Errorf("events = %v, want the API message in the detail", eventSummary(events))
	}
}

func TestAliyunCDNRequiresCredentials(t *testing.T) {
	if _, err := newAliyunCDN(`{"cdn_domain":"c"}`); err == nil {
		t.Error("newAliyunCDN without credentials = nil error, want failure")
	}
}

func TestTencentCDNDeploy(t *testing.T) {
	var gotBody, gotAuth, gotAction string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAction = r.Header.Get("X-TC-Action")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Write([]byte(`{"Response":{"RequestId":"req-1"}}`))
	}))
	defer srv.Close()

	target, err := newTencentCDN(`{"secret_id":"AKID","secret_key":"SK","cdn_domain":"cdn.example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	tc := target.(*tencentCDN)
	tc.url = srv.URL
	tc.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	events, err := tc.Deploy(context.Background(), testCert())
	if err != nil {
		t.Fatalf("Deploy() = %v", err)
	}

	if !strings.Contains(gotAuth, "TC3-HMAC-SHA256 Credential=AKID/") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotAction != "UpdateDomainConfig" {
		t.Errorf("X-TC-Action = %q", gotAction)
	}

	var body struct {
		Domain string `json:"Domain"`
		Https  struct {
			Switch   string `json:"Switch"`
			CertInfo struct {
				Certificate string `json:"Certificate"`
				PrivateKey  string `json:"PrivateKey"`
			} `json:"CertInfo"`
		} `json:"Https"`
	}
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Domain != "cdn.example.com" {
		t.Errorf("Domain = %q", body.Domain)
	}
	if body.Https.Switch != "on" {
		t.Errorf("Https.Switch = %q, want on", body.Https.Switch)
	}
	// 完整链，不是只有叶子。
	if !strings.Contains(body.Https.CertInfo.Certificate, "LEAF-PEM") ||
		!strings.Contains(body.Https.CertInfo.Certificate, "CHAIN-PEM") {
		t.Errorf("Certificate = %q, want the full chain", body.Https.CertInfo.Certificate)
	}
	if body.Https.CertInfo.PrivateKey != "KEY-PEM\n" {
		t.Errorf("PrivateKey = %q", body.Https.CertInfo.PrivateKey)
	}
	if !hasEvent(events, "tencent_cdn", "installed") {
		t.Errorf("events = %v", eventSummary(events))
	}
}

func TestTencentCDNErrorInsideTwoHundred(t *testing.T) {
	// 腾讯把 API 错误放在 200 响应体里，只看状态码会把失败当成功。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"Response":{"Error":{"Code":"InvalidParameter","Message":"bad cert"},"RequestId":"r"}}`))
	}))
	defer srv.Close()

	target, _ := newTencentCDN(`{"secret_id":"i","secret_key":"k","cdn_domain":"c"}`)
	tc := target.(*tencentCDN)
	tc.url = srv.URL

	events, err := tc.Deploy(context.Background(), testCert())
	if err == nil {
		t.Fatal("Deploy = nil error, want the in-body error detected")
	}
	if !strings.Contains(err.Error(), "InvalidParameter") {
		t.Errorf("error = %v", err)
	}
	if !hasEvent(events, "tencent_cdn", "bad cert") {
		t.Errorf("events = %v", eventSummary(events))
	}
}

func TestTencentCDNRequiresCredentials(t *testing.T) {
	if _, err := newTencentCDN(`{"cdn_domain":"c"}`); err == nil {
		t.Error("newTencentCDN without credentials = nil error, want failure")
	}
}
