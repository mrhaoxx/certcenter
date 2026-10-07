// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// authed issues a request carrying a valid session.
func authed(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
}

// seedProvider adds a DNS provider directly, bypassing the API.
func seedProvider(t *testing.T, srv *Server) int64 {
	t.Helper()
	id, err := srv.DB.CreateDNSProvider(context.Background(), db.DNSProvider{
		Name: "cf", Kind: "cloudflare", Config: `{"api_token":"t","zone_id":"z"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func seedAccount(t *testing.T, srv *Server) int64 {
	t.Helper()
	url := "https://acme.example/acct/1"
	id, err := srv.DB.CreateACMEAccount(context.Background(), db.ACMEAccount{
		Name: "le", DirectoryURL: "https://acme.example/dir", Email: "a@b.c",
		AccountURL: &url, PrivateKeyPEM: "PEM", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAllAPIRoutesRequireASession(t *testing.T) {
	srv := newTestServer(t)
	paths := []struct{ method, path string }{
		{http.MethodGet, "/api/dashboard"},
		{http.MethodGet, "/api/logs"},
		{http.MethodGet, "/api/certificates"},
		{http.MethodPost, "/api/certificates"},
		{http.MethodGet, "/api/certificates/1"},
		{http.MethodGet, "/api/acme-accounts"},
		{http.MethodGet, "/api/dns-providers"},
		{http.MethodGet, "/api/deploy-targets"},
		{http.MethodGet, "/api/events?topics=certificates"},
	}
	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			req := httptest.NewRequest(p.method, p.path, strings.NewReader("{}"))
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 without a session", rec.Code)
			}
		})
	}
}

func TestDNSProviderCRUDOverAPI(t *testing.T) {
	srv := newTestServer(t)

	rec := authed(t, srv, http.MethodPost, "/api/dns-providers",
		`{"name":"cf","kind":"cloudflare","config":"{\"api_token\":\"t\",\"zone_id\":\"z\"}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201, body = %s", rec.Code, rec.Body)
	}
	var created db.DNSProvider
	decodeInto(t, rec, &created)
	if created.ID == 0 || created.Name != "cf" {
		t.Fatalf("created = %+v", created)
	}

	rec = authed(t, srv, http.MethodGet, "/api/dns-providers", "")
	var list []db.DNSProvider
	decodeInto(t, rec, &list)
	if len(list) != 1 {
		t.Errorf("list = %d entries, want 1", len(list))
	}

	rec = authed(t, srv, http.MethodPatch, fmt.Sprintf("/api/dns-providers/%d", created.ID),
		`{"name":"cloudflare-prod"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body = %s", rec.Code, rec.Body)
	}

	rec = authed(t, srv, http.MethodDelete, fmt.Sprintf("/api/dns-providers/%d", created.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", rec.Code)
	}
}

func TestCreateDNSProviderValidatesConfig(t *testing.T) {
	// Rust 版写入时不做任何校验，坏配置要到凌晨续期失败才暴露。
	srv := newTestServer(t)
	tests := []struct{ name, body string }{
		{"未知类型", `{"name":"x","kind":"route53","config":"{}"}`},
		{"缺必填字段", `{"name":"x","kind":"cloudflare","config":"{}"}`},
		{"配置不是 JSON", `{"name":"x","kind":"cloudflare","config":"nope"}`},
		{"名称为空", `{"name":"","kind":"cloudflare","config":"{\"api_token\":\"t\",\"zone_id\":\"z\"}"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := authed(t, srv, http.MethodPost, "/api/dns-providers", tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body = %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestCreateDeployTargetValidatesPipeline(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		name, body string
		wantStatus int
	}{
		{"含 ssh 的流水线",
			`{"name":"web","kind":"pipeline","config":"{\"steps\":[{\"type\":\"ssh_connect\",\"name\":\"c\",\"config\":{\"host\":\"h\",\"auth_type\":\"password\"}}]}"}`,
			http.StatusCreated},
		// A pipeline needs no shell: writing locally and calling a reload
		// endpoint is a complete deployment on its own.
		{"不含 ssh 的流水线",
			`{"name":"local","kind":"pipeline","config":"{\"steps\":[{\"type\":\"local_write\",\"name\":\"w\",\"config\":{\"path\":\"/tmp/c.pem\"}}]}"}`,
			http.StatusCreated},
		{"空流水线", `{"name":"e","kind":"pipeline","config":"{\"steps\":[]}"}`, http.StatusBadRequest},
		// The old kinds are gone; each is a step now.
		{"旧的 ssh 类型", `{"name":"w","kind":"ssh","config":"{}"}`, http.StatusBadRequest},
		{"旧的 webhook 类型", `{"name":"w","kind":"webhook","config":"{}"}`, http.StatusBadRequest},
		{"未知类型", `{"name":"w","kind":"telegram","config":"{}"}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := authed(t, srv, http.MethodPost, "/api/deploy-targets", tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body = %s", rec.Code, tt.wantStatus, rec.Body)
			}
		})
	}
}

func TestDeleteInUseResourceReturns409(t *testing.T) {
	// Rust 版会静默级联，把绑定删掉并让事件表变成孤儿。
	srv := newTestServer(t)
	ctx := context.Background()
	acctID := seedAccount(t, srv)
	dnsID := seedProvider(t, srv)
	if _, err := srv.DB.CreateCertificate(ctx, db.Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		fmt.Sprintf("/api/dns-providers/%d", dnsID),
		fmt.Sprintf("/api/acme-accounts/%d", acctID),
	} {
		rec := authed(t, srv, http.MethodDelete, path, "")
		if rec.Code != http.StatusConflict {
			t.Errorf("DELETE %s = %d, want 409 while still referenced", path, rec.Code)
		}
		var body apiError
		decodeInto(t, rec, &body)
		if body.Code != "IN_USE" {
			t.Errorf("code = %q, want IN_USE", body.Code)
		}
	}
}

func TestCertificateLifecycleOverAPI(t *testing.T) {
	srv := newTestServer(t)
	acctID := seedAccount(t, srv)
	dnsID := seedProvider(t, srv)

	rec := authed(t, srv, http.MethodPost, "/api/certificates", fmt.Sprintf(
		`{"domain":"example.com","sans":["*.example.com"],"acmeAccountId":%d,"dnsProviderId":%d}`,
		acctID, dnsID))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body)
	}
	var cert db.Certificate
	decodeInto(t, rec, &cert)
	if cert.Domain != "example.com" || len(cert.SANs) != 1 {
		t.Errorf("certificate = %+v", cert)
	}
	if cert.Status != "pending" {
		t.Errorf("status = %q, want pending", cert.Status)
	}

	rec = authed(t, srv, http.MethodGet, "/api/certificates?search=example", "")
	var list []db.Certificate
	decodeInto(t, rec, &list)
	if len(list) != 1 {
		t.Errorf("search returned %d entries, want 1", len(list))
	}

	// 尚未签发时，bundle 与 x509 都应拒绝而不是回半份数据。
	for _, path := range []string{"bundle", "x509"} {
		rec = authed(t, srv, http.MethodGet, fmt.Sprintf("/api/certificates/%d/%s", cert.ID, path), "")
		if rec.Code != http.StatusConflict {
			t.Errorf("GET %s on a pending certificate = %d, want 409", path, rec.Code)
		}
	}

	autoRenewOff := `{"autoRenew":false}`
	rec = authed(t, srv, http.MethodPatch, fmt.Sprintf("/api/certificates/%d", cert.ID), autoRenewOff)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, body = %s", rec.Code, rec.Body)
	}
	decodeInto(t, rec, &cert)
	if cert.AutoRenew {
		t.Error("autoRenew still true after the patch")
	}

	rec = authed(t, srv, http.MethodDelete, fmt.Sprintf("/api/certificates/%d", cert.ID), "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", rec.Code)
	}
}

func TestCreateCertificateRejectsDanglingReferences(t *testing.T) {
	srv := newTestServer(t)
	dnsID := seedProvider(t, srv)

	rec := authed(t, srv, http.MethodPost, "/api/certificates", fmt.Sprintf(
		`{"domain":"e.com","acmeAccountId":999,"dnsProviderId":%d}`, dnsID))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a missing account", rec.Code)
	}
}

func TestCertificatePrivateKeyOnlyViaBundle(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	acctID := seedAccount(t, srv)
	dnsID := seedProvider(t, srv)
	certID, err := srv.DB.CreateCertificate(ctx, db.Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = srv.DB.SaveIssuedCertificate(ctx, certID, db.IssuedCertificate{
		CertPEM: "LEAF", ChainPEM: "INTER", KeyPEM: "SECRET-KEY-MATERIAL",
		Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 列表与详情都不能带出私钥。
	for _, path := range []string{"/api/certificates", fmt.Sprintf("/api/certificates/%d", certID)} {
		rec := authed(t, srv, http.MethodGet, path, "")
		if strings.Contains(rec.Body.String(), "SECRET-KEY-MATERIAL") {
			t.Errorf("GET %s leaked the private key", path)
		}
	}

	// bundle 是唯一出口，且必须留下审计记录。
	rec := authed(t, srv, http.MethodGet, fmt.Sprintf("/api/certificates/%d/bundle", certID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle status = %d, body = %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "SECRET-KEY-MATERIAL") {
		t.Error("the bundle did not include the private key")
	}
	logs, err := srv.DB.ListLogs(ctx, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sawDownload bool
	for _, l := range logs {
		if l.Action == "download" {
			sawDownload = true
		}
	}
	if !sawDownload {
		t.Error("downloading the bundle was not audited")
	}
}

func TestSSEStreamsTopicSignals(t *testing.T) {
	// 签发要跑一两分钟，没有这条流 UI 就只能轮询——正是 Rust 版的处境。
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events?topics=certificates", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		srv.Routes().ServeHTTP(rec, req)
		close(done)
	}()

	// 等订阅建立后再发布。
	deadline := time.After(2 * time.Second)
	for {
		srv.Events.Publish(TopicCertificates)
		if strings.Contains(rec.Body.String(), "event: certificates") {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("no SSE signal arrived; body = %q", rec.Body.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

func TestSSERequiresTopics(t *testing.T) {
	srv := newTestServer(t)
	rec := authed(t, srv, http.MethodGet, "/api/events", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 when no topics are requested", rec.Code)
	}
}

func TestDashboardCounts(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	acctID := seedAccount(t, srv)
	dnsID := seedProvider(t, srv)

	// 一张已签发且还早，一张即将过期，一张已过期。
	mk := func(domain string, notAfter time.Time) {
		id, err := srv.DB.CreateCertificate(ctx, db.Certificate{
			Domain: domain, ACMEAccountID: acctID, DNSProviderID: dnsID,
			ValidityDays: 90, AutoRenew: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = srv.DB.SaveIssuedCertificate(ctx, id, db.IssuedCertificate{
			CertPEM: "L", ChainPEM: "I", KeyPEM: "K", Serial: "01",
			NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mk("fresh.example.com", time.Now().Add(80*24*time.Hour))
	mk("soon.example.com", time.Now().Add(5*24*time.Hour))
	mk("gone.example.com", time.Now().Add(-24*time.Hour))

	rec := authed(t, srv, http.MethodGet, "/api/dashboard", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var stats map[string]int
	decodeInto(t, rec, &stats)
	if stats["totalCertificates"] != 3 {
		t.Errorf("totalCertificates = %d, want 3", stats["totalCertificates"])
	}
	if stats["expiringSoon"] != 1 {
		t.Errorf("expiringSoon = %d, want 1", stats["expiringSoon"])
	}
	if stats["expired"] != 1 {
		t.Errorf("expired = %d, want 1", stats["expired"])
	}
	if stats["acmeAccounts"] != 1 {
		t.Errorf("acmeAccounts = %d, want 1", stats["acmeAccounts"])
	}
}

func TestRunsAndEventsOverAPI(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()
	acctID := seedAccount(t, srv)
	dnsID := seedProvider(t, srv)
	certID, err := srv.DB.CreateCertificate(ctx, db.Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := srv.DB.StartRun(ctx, db.RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.DB.AppendEvent(ctx, run.ID, db.Event{
		Type: "start", Message: "Starting", Level: db.LevelInfo,
	}); err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, http.MethodGet, fmt.Sprintf("/api/certificates/%d/runs", certID), "")
	var runs []db.Run
	decodeInto(t, rec, &runs)
	if len(runs) != 1 || runs[0].Kind != db.RunKindIssue {
		t.Fatalf("runs = %+v", runs)
	}

	rec = authed(t, srv, http.MethodGet, fmt.Sprintf("/api/runs/%d/events", run.ID), "")
	var events []db.Event
	decodeInto(t, rec, &events)
	if len(events) != 1 || events[0].Type != "start" {
		t.Errorf("events = %+v", events)
	}
}

func TestInvalidIDsAre400(t *testing.T) {
	srv := newTestServer(t)
	for _, path := range []string{
		"/api/certificates/abc",
		"/api/dns-providers/abc",
		"/api/runs/abc/events",
	} {
		rec := authed(t, srv, http.MethodGet, path, "")
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 400", path, rec.Code)
		}
	}
}
