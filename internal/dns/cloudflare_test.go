// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newCloudflareWith builds a provider pointed at a test server.
func newCloudflareWith(t *testing.T, baseURL string) *cloudflare {
	t.Helper()
	return &cloudflare{token: "test-token", zoneID: "zone123", baseURL: baseURL}
}

func TestCloudflareAddTXT(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "digest-value"); err != nil {
		t.Fatalf("AddTXT() = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/zones/zone123/dns_records"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := "Bearer test-token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}

	var body struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body is not JSON: %v (%q)", err, gotBody)
	}
	if body.Type != "TXT" {
		t.Errorf("type = %q, want TXT", body.Type)
	}
	if body.Name != "_acme-challenge.example.com" {
		t.Errorf("name = %q", body.Name)
	}
	if body.Content != "digest-value" {
		t.Errorf("content = %q", body.Content)
	}
	if body.TTL != cloudflareTXTTTL {
		t.Errorf("ttl = %d, want %d", body.TTL, cloudflareTXTTTL)
	}
}

func TestCloudflareAddTXTDoesNotDeleteFirst(t *testing.T) {
	// 回归测试：apex + 通配符同证书时，两个授权的记录名相同而摘要不同。
	// 添加前若先删同名记录，后一个挑战会毁掉前一个，第一个授权随即验证失败。
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "first"); err != nil {
		t.Fatal(err)
	}
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "second"); err != nil {
		t.Fatal(err)
	}

	for _, m := range methods {
		if m == http.MethodDelete {
			t.Fatalf("AddTXT issued a DELETE; requests = %v, want POST only", methods)
		}
	}
	if len(methods) != 2 {
		t.Errorf("requests = %v, want exactly two POSTs", methods)
	}
}

func TestCloudflareAddTXTRejectsSuccessFalse(t *testing.T) {
	// Rust 版只看 HTTP 状态码：200 + success:false 被当成成功，
	// 于是记录其实没建上，签发却继续往下走直到超时。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":false,"errors":[{"code":1004,"message":"DNS Validation Error"}]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("AddTXT with success:false = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "DNS Validation Error") {
		t.Errorf("error = %v, want it to surface the API message", err)
	}
}

func TestCloudflareAddTXTRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v"); err == nil {
		t.Fatal("AddTXT on 403 = nil error, want failure")
	}
}

func TestCloudflareRemoveTXTDeletesOnlyExactMatch(t *testing.T) {
	// 服务端过滤语义在新版 API 里有 name.exact 之类的修饰符，不能依赖；
	// 客户端必须自己做精确匹配，否则会删掉别的挑战的记录。
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"success":true,"errors":[],"result":[
			  {"id":"want","type":"TXT","name":"_acme-challenge.example.com","content":"target"},
			  {"id":"other-value","type":"TXT","name":"_acme-challenge.example.com","content":"sibling"},
			  {"id":"other-name","type":"TXT","name":"_acme-challenge.sub.example.com","content":"target"}
			]}`))
		case http.MethodDelete:
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			deleted = append(deleted, parts[len(parts)-1])
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"x"}}`))
		}
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "want" {
		t.Errorf("deleted = %v, want exactly [want]", deleted)
	}
}

func TestCloudflareRemoveTXTIsIdempotent(t *testing.T) {
	// 清理路径会在失败重试后重复执行；记录已不存在必须视为成功。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.RemoveTXT(context.Background(), "_acme-challenge.example.com", "gone"); err != nil {
		t.Errorf("RemoveTXT with no matching record = %v, want nil", err)
	}
}

func TestCloudflareContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(ctx, "_acme-challenge.example.com", "v"); err == nil {
		t.Error("AddTXT with a cancelled context = nil error, want failure")
	}
}

func TestNewCloudflareUsesRealEndpointByDefault(t *testing.T) {
	p, err := newCloudflare(`{"api_token":"t","zone_id":"z"}`)
	if err != nil {
		t.Fatal(err)
	}
	cf, ok := p.(*cloudflare)
	if !ok {
		t.Fatalf("newCloudflare returned %T, want *cloudflare", p)
	}
	if cf.baseURL != cloudflareAPI {
		t.Errorf("baseURL = %q, want %q", cf.baseURL, cloudflareAPI)
	}
}

func TestCloudflareDiscoversZoneFromRecordName(t *testing.T) {
	// zone_id 留空时按记录名逐级向上找 zone，用户不必去 Cloudflare
	// 控制台翻 ID。
	var zoneQueries []string
	var recordPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/zones") && r.Method == http.MethodGet &&
			!strings.Contains(r.URL.Path, "dns_records") {
			name := r.URL.Query().Get("name")
			zoneQueries = append(zoneQueries, name)
			if name == "example.com" {
				w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"zone-abc","name":"example.com"}]}`))
				return
			}
			w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
			return
		}
		recordPath = r.URL.Path
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
	if err := p.AddTXT(context.Background(), "_acme-challenge.a.example.com", "v"); err != nil {
		t.Fatalf("AddTXT() = %v", err)
	}

	// 从最长的名字开始逐级缩短，命中 example.com 后停止。
	want := []string{"_acme-challenge.a.example.com", "a.example.com", "example.com"}
	if len(zoneQueries) != len(want) {
		t.Fatalf("zone queries = %v, want %v", zoneQueries, want)
	}
	for i := range want {
		if zoneQueries[i] != want[i] {
			t.Errorf("zone queries = %v, want %v", zoneQueries, want)
			break
		}
	}
	if recordPath != "/zones/zone-abc/dns_records" {
		t.Errorf("record written to %q, want the discovered zone", recordPath)
	}
}

func TestCloudflareExplicitZoneIDSkipsDiscovery(t *testing.T) {
	// 填了 zone_id 就直接用——这样窄权限 token（只有 Zone:DNS:Edit、
	// 不能列 zone）依然可用。
	var listedZones bool
	var recordPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "" && !strings.Contains(r.URL.Path, "dns_records") {
			listedZones = true
		}
		recordPath = r.URL.Path
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if listedZones {
		t.Error("an explicit zone_id must not trigger a zone lookup")
	}
	if recordPath != "/zones/zone123/dns_records" {
		t.Errorf("record written to %q, want the configured zone", recordPath)
	}
}

func TestCloudflareZoneDiscoveryIsCached(t *testing.T) {
	var zoneLookups int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("name") != "" && !strings.Contains(r.URL.Path, "dns_records") {
			zoneLookups++
			w.Write([]byte(`{"success":true,"errors":[],"result":[{"id":"z1","name":"example.com"}]}`))
			return
		}
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v"); err != nil {
		t.Fatal(err)
	}
	// The first call walks up the labels, so more than one lookup is
	// expected; what matters is that later calls add none.
	afterFirst := zoneLookups
	if afterFirst == 0 {
		t.Fatal("the first call performed no zone lookup")
	}
	for i := 0; i < 3; i++ {
		if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v"); err != nil {
			t.Fatal(err)
		}
	}
	if zoneLookups != afterFirst {
		t.Errorf("zone looked up %d times after the first call resolved it in %d; want no further lookups",
			zoneLookups, afterFirst)
	}
}

func TestCloudflareZoneDiscoveryErrors(t *testing.T) {
	t.Run("找不到 zone 时提示明确", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
		}))
		defer srv.Close()

		p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
		err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v")
		if err == nil {
			t.Fatal("AddTXT with no matching zone = nil error, want failure")
		}
		if !strings.Contains(err.Error(), "zone_id") {
			t.Errorf("error = %v, want it to suggest setting zone_id", err)
		}
	})

	t.Run("权限不足时点明需要 Zone:Read", func(t *testing.T) {
		// 只有 Zone:DNS:Edit 的 token 列 zone 会被拒；错误必须说清
		// 要么加权限、要么填 zone_id，而不是笼统的"找不到"。
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`))
		}))
		defer srv.Close()

		p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
		err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v")
		if err == nil {
			t.Fatal("AddTXT = nil error, want the permission failure surfaced")
		}
		if !strings.Contains(err.Error(), "Zone:Read") {
			t.Errorf("error = %v, want it to name the missing permission", err)
		}
	})
}

func TestNewCloudflareAcceptsMissingZoneID(t *testing.T) {
	// zone_id 现在可选；api_token 仍然必填。
	if _, err := newCloudflare(`{"api_token":"t"}`); err != nil {
		t.Errorf("newCloudflare without zone_id = %v, want it accepted", err)
	}
	if _, err := newCloudflare(`{"zone_id":"z"}`); err == nil {
		t.Error("newCloudflare without api_token = nil error, want failure")
	}
}

func TestCloudflareAmbiguousZoneIsRefused(t *testing.T) {
	// 同名 zone 出现多个（token 跨账户，或域名迁移中间态）时，随便挑
	// 一个会把挑战记录写进错误的 zone，验证静默失败。宁可报错。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"errors":[],"result":[
		  {"id":"zone-a","name":"example.com"},
		  {"id":"zone-b","name":"example.com"}
		]}`))
	}))
	defer srv.Close()

	p := &cloudflare{token: "t", baseURL: srv.URL, discovered: map[string]string{}}
	err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("AddTXT with two matching zones = nil error, want a refusal")
	}
	for _, want := range []string{"ambiguous", "zone-a", "zone-b", "zone_id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}
}
