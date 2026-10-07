// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newAliyunWith(t *testing.T, endpoint, domain string) *aliyun {
	t.Helper()
	return &aliyun{
		keyID:     "test-key",
		keySecret: "test-secret",
		domain:    domain,
		endpoint:  endpoint,
		now:       func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		nonce:     func() string { return "fixed-nonce" },
	}
}

func TestAliyunRecordRR(t *testing.T) {
	tests := []struct {
		name, domain, fqdn, want string
		wantErr                  bool
	}{
		{"子域", "example.com", "_acme-challenge.sub.example.com", "_acme-challenge.sub", false},
		{"顶级域本身", "example.com", "_acme-challenge.example.com", "_acme-challenge", false},
		{"多级配置域", "sub.example.com", "_acme-challenge.sub.example.com", "_acme-challenge", false},
		{"后缀不匹配必须报错", "example.com", "_acme-challenge.other.com", "", true},
		{"仅部分匹配也要报错", "example.com", "_acme-challenge.notexample.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAliyunWith(t, "http://unused", tt.domain)
			got, err := a.recordRR(tt.fqdn)
			if tt.wantErr {
				// Rust 版在这里静默用整个 FQDN 当 RR，于是在错误的 zone 里
				// 建出 "_acme-challenge.other.com"，验证莫名失败。
				if err == nil {
					t.Fatalf("recordRR(%q) with domain %q = %q, nil; want an error",
						tt.fqdn, tt.domain, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("recordRR() = %v", err)
			}
			if got != tt.want {
				t.Errorf("recordRR(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestAliyunAddTXT(t *testing.T) {
	var gotQuery url.Values
	var gotRawQuery, gotAuth, gotDate, gotNonce, gotAction string
	var gotBodyLen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		gotQuery = r.URL.Query()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("x-acs-date")
		gotNonce = r.Header.Get("x-acs-signature-nonce")
		gotAction = r.Header.Get("x-acs-action")
		gotBodyLen = r.ContentLength
		w.Write([]byte(`{"RecordId":"123","RequestId":"abc"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("AddTXT() = %v", err)
	}

	if gotAction != "AddDomainRecord" {
		t.Errorf("x-acs-action = %q, want AddDomainRecord", gotAction)
	}
	if gotQuery.Get("DomainName") != "example.com" {
		t.Errorf("DomainName = %q", gotQuery.Get("DomainName"))
	}
	if gotQuery.Get("RR") != "_acme-challenge" {
		t.Errorf("RR = %q, want _acme-challenge", gotQuery.Get("RR"))
	}
	if gotQuery.Get("Type") != "TXT" {
		t.Errorf("Type = %q, want TXT", gotQuery.Get("Type"))
	}
	if gotQuery.Get("Value") != "digest" {
		t.Errorf("Value = %q, want digest", gotQuery.Get("Value"))
	}
	if !strings.HasPrefix(gotAuth, "ACS3-HMAC-SHA256 Credential=test-key,") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotDate != "2023-11-14T22:13:20Z" {
		t.Errorf("x-acs-date = %q, want the injected clock's value", gotDate)
	}
	if gotNonce != "fixed-nonce" {
		t.Errorf("x-acs-signature-nonce = %q", gotNonce)
	}
	if gotBodyLen > 0 {
		t.Errorf("Content-Length = %d, want an empty body (params ride in the query)", gotBodyLen)
	}
	// 发送的查询串必须与签名的一致：参数按 key 排序、空格编成 %20。
	if strings.Contains(gotRawQuery, "+") {
		t.Errorf("raw query %q contains '+', signature would not verify", gotRawQuery)
	}
}

func TestAliyunAddTXTTreatsDuplicateAsSuccess(t *testing.T) {
	// 同 RR + 同 Value 的记录已存在，说明期望状态已达成，应视为成功。
	// Rust 版在这里会列出该 RR 下所有 TXT 记录并全部删除后重试——
	// 那会连带删掉 apex/通配符场景下兄弟挑战的记录。
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "AddDomainRecord":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"Code":"DomainRecordDuplicate","Message":"Domain record duplicate"}`))
		case "DeleteDomainRecord":
			deleteCalls++
			w.Write([]byte(`{"RequestId":"x"}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Errorf("AddTXT on DomainRecordDuplicate = %v, want nil (desired state already holds)", err)
	}
	if deleteCalls != 0 {
		t.Errorf("AddTXT issued %d DELETEs, want 0 — deleting would destroy a sibling challenge", deleteCalls)
	}
}

func TestAliyunAddTXTPropagatesOtherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"Code":"SignatureDoesNotMatch","Message":"signature mismatch"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest")
	if err == nil {
		t.Fatal("AddTXT = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("error = %v, want it to surface the API Code", err)
	}
}

func TestAliyunAddTXTRejectsSuccessBodyWithErrorCode(t *testing.T) {
	// 2xx 但 body 带 Code 的情况：Rust 版直接返回泛型 JSON 不做检查。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"Code":"Throttling.User","Message":"Request was denied due to user flow control"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "d"); err == nil {
		t.Error("AddTXT with an error Code in a 200 body = nil error, want failure")
	}
}

func TestAliyunRemoveTXTDeletesOnlyExactMatch(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "DescribeDomainRecords":
			w.Write([]byte(`{"TotalCount":3,"PageNumber":1,"PageSize":100,"DomainRecords":{"Record":[
			  {"RecordId":"want","RR":"_acme-challenge","Type":"TXT","Value":"target"},
			  {"RecordId":"other-value","RR":"_acme-challenge","Type":"TXT","Value":"sibling"},
			  {"RecordId":"other-type","RR":"_acme-challenge","Type":"A","Value":"target"}
			]}}`))
		case "DeleteDomainRecord":
			deleted = append(deleted, r.URL.Query().Get("RecordId"))
			w.Write([]byte(`{"RequestId":"x"}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "want" {
		t.Errorf("deleted = %v, want exactly [want]", deleted)
	}
}

func TestAliyunRemoveTXTPaginates(t *testing.T) {
	// AliDNS 默认每页 20 条。Rust 版不翻页，一个域名下 TXT 记录多了就
	// 漏删，challenge 记录残留。
	var pages []string
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "DescribeDomainRecords":
			page := r.URL.Query().Get("PageNumber")
			pages = append(pages, page)
			// TotalCount 与实际返回条数保持自洽：共 2 条、每页 1 条，
			// 于是必须取到第二页才算读完。
			if page == "1" {
				w.Write([]byte(`{"TotalCount":2,"PageNumber":1,"PageSize":1,"DomainRecords":{"Record":[
				  {"RecordId":"p1","RR":"_acme-challenge","Type":"TXT","Value":"nope"}
				]}}`))
				return
			}
			w.Write([]byte(`{"TotalCount":2,"PageNumber":2,"PageSize":1,"DomainRecords":{"Record":[
			  {"RecordId":"p2","RR":"_acme-challenge","Type":"TXT","Value":"target"}
			]}}`))
		case "DeleteDomainRecord":
			deleted = append(deleted, r.URL.Query().Get("RecordId"))
			w.Write([]byte(`{"RequestId":"x"}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(pages) < 2 {
		t.Errorf("requested pages = %v, want it to fetch beyond page 1", pages)
	}
	if len(deleted) != 1 || deleted[0] != "p2" {
		t.Errorf("deleted = %v, want [p2] from the second page", deleted)
	}
}

func TestAliyunRemoveTXTIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"TotalCount":0,"PageNumber":1,"PageSize":100,"DomainRecords":{"Record":[]}}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "gone"); err != nil {
		t.Errorf("RemoveTXT with no matching record = %v, want nil", err)
	}
}

func TestAliyunRejectsRRMismatchBeforeCallingAPI(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.other.com", "d"); err == nil {
		t.Error("AddTXT with a mismatched zone = nil error, want failure")
	}
	if called {
		t.Error("AddTXT called the API despite the zone mismatch")
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	// 正向用例放在这里而不是 Task 1：两个 provider 都实现之后，
	// New 才真的能返回可用实例。
	tests := []struct{ kind, config string }{
		{KindCloudflare, `{"api_token":"t","zone_id":"z"}`},
		{KindAliyun, `{"access_key_id":"k","access_key_secret":"s","domain":"example.com"}`},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			p, err := New(tt.kind, tt.config)
			if err != nil {
				t.Fatalf("New = %v", err)
			}
			if p == nil {
				t.Fatal("New returned a nil Provider with no error")
			}
		})
	}
}

func TestNewAliyunUsesRealEndpointByDefault(t *testing.T) {
	p, err := newAliyun(`{"access_key_id":"k","access_key_secret":"s","domain":"example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := p.(*aliyun)
	if !ok {
		t.Fatalf("newAliyun returned %T, want *aliyun", p)
	}
	if a.endpoint != aliyunEndpoint {
		t.Errorf("endpoint = %q, want %q", a.endpoint, aliyunEndpoint)
	}
	if a.now == nil || a.nonce == nil {
		t.Error("now/nonce must be populated so signing works outside tests")
	}
}
