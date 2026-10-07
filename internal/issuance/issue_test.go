// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/dns"
)

// newTestIssuer wires an Issuer against the in-process CA and a store.
func newTestIssuer(t *testing.T, caSrv *testCA) *Issuer {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	return &Issuer{
		Store:      store,
		Registrar:  &Registrar{HTTPClient: caSrv.HTTPClient},
		HTTPClient: caSrv.HTTPClient,
		// Propagation is enforced by the CA itself here, so the DoH check
		// (which would query the public internet) is skipped.
		DoH:         func() DoHSettings { return DoHSettings{Skip: true} },
		NewProvider: func(string, string) (dns.Provider, error) { return caSrv.DNS, nil },
	}
}

// seedIssuable creates an account registered at the test CA, a DNS provider
// row, and a pending certificate; it returns the certificate id.
func seedIssuable(t *testing.T, is *Issuer, caSrv *testCA, domain string, sans []string) int64 {
	t.Helper()
	ctx := context.Background()

	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	accountURL, err := is.Registrar.Register(ctx, Registration{
		DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c", KeyPEM: keyPEM,
	})
	if err != nil {
		t.Fatalf("registering the test account: %v", err)
	}
	acctID, err := is.Store.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "pebble", DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c",
		AccountURL: &accountURL, PrivateKeyPEM: keyPEM, ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}

	sqlStore := is.Store.(*db.SQLite)
	res, err := sqlStore.DB.Exec(
		`INSERT INTO dns_providers (name, kind, config) VALUES ('fake','cloudflare','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	certID, err := is.Store.CreateCertificate(ctx, db.Certificate{
		Domain: domain, SANs: sans, ACMEAccountID: acctID, DNSProviderID: dnsID,
		AutoRenew: true, // ValidityDays stays 0: request no particular lifetime

	})
	if err != nil {
		t.Fatal(err)
	}
	return certID
}

func TestIssueEndToEnd(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", []string{"*.example.com"})

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "issued" {
		t.Fatalf("status = %q, want issued (last error: %v)", cert.Status, cert.LastError)
	}

	// 叶子与链分开存。
	if cert.CertPEM == nil || cert.ChainPEM == nil {
		t.Fatal("cert_pem or chain_pem is nil")
	}
	if n := strings.Count(*cert.CertPEM, "BEGIN CERTIFICATE"); n != 1 {
		t.Errorf("cert_pem holds %d certificates, want exactly the leaf", n)
	}
	if *cert.CertPEM == *cert.ChainPEM {
		t.Error("cert_pem equals chain_pem; the leaf was not split from the chain")
	}
	if cert.KeyPEM == "" {
		t.Error("no private key stored")
	}

	// 日期来自真实证书，不是按 validity_days 估算。
	if cert.NotBefore == nil || cert.NotAfter == nil {
		t.Fatal("not_before/not_after not populated")
	}
	nb, err := time.Parse(time.RFC3339, *cert.NotBefore)
	if err != nil {
		t.Fatalf("not_before is not RFC3339: %v", err)
	}
	na, err := time.Parse(time.RFC3339, *cert.NotAfter)
	if err != nil {
		t.Fatalf("not_after is not RFC3339: %v", err)
	}
	if days := na.Sub(nb).Hours() / 24; days < 80 || days > 100 {
		t.Errorf("validity = %.1f days, want the CA's real ~90", days)
	}
	if cert.Serial == nil || *cert.Serial == "" {
		t.Error("serial not recorded")
	}

	// TXT 记录清理干净。
	if got := caSrv.DNS.Values("_acme-challenge.example.com"); len(got) != 0 {
		t.Errorf("challenge records left behind: %v", got)
	}
}

func TestIssueWritesTheEventTimeline(t *testing.T) {
	// Rust 版的 log 闭包是同步闭包，内部调 async fn 后立即丢弃 future，
	// 约 40 处调用全是空操作，certificate_events 永远为空。这个测试就是
	// 钉死"事件真的落库了"。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Kind != db.RunKindIssue {
		t.Errorf("run kind = %q, want %q", run.Kind, db.RunKindIssue)
	}
	if run.Status != db.RunStatusSuccess {
		t.Errorf("run status = %q, want %q", run.Status, db.RunStatusSuccess)
	}
	if run.Trigger != "manual" {
		t.Errorf("run trigger = %q, want manual", run.Trigger)
	}
	if run.FinishedAt == nil {
		t.Error("run not finished")
	}

	events, err := is.Store.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 10 {
		t.Fatalf("only %d events; the timeline must cover every phase", len(events))
	}

	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Type] = true
	}
	// 每个阶段都要有事件——这是选 acmez 而非 lego 换来的粒度。
	for _, want := range []string{
		"start", "load_account", "load_dns_provider", "acme_connect",
		"create_order", "get_authorizations", "dns_add", "challenge_ready",
		"poll_order", "generate_csr", "finalize_order", "download_cert",
		"save_cert", "dns_cleanup", "complete",
	} {
		if !seen[want] {
			t.Errorf("timeline is missing a %q event", want)
		}
	}

	if events[0].Type != "start" {
		t.Errorf("events[0].Type = %q, want start", events[0].Type)
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestIssueRecordsFailureAndCleansUp(t *testing.T) {
	// 失败路径必须：证书置 error、run 置 error、错误事件落库，且已写入的
	// TXT 记录被清理——Rust 版只在成功路径清理，失败后记录永久残留。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	// 让挑战无法通过：TXT 写进假 provider 但不同步到 DNS 服务器。
	caSrv.DNS.SuppressDNSSync = true

	if err := is.Issue(ctx, certID, "auto"); err == nil {
		t.Fatal("Issue() = nil error, want failure when the challenge cannot validate")
	}

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "error" {
		t.Errorf("status = %q, want error", cert.Status)
	}
	if cert.LastError == nil || *cert.LastError == "" {
		t.Error("last_error not recorded")
	}

	runs, _ := is.Store.ListRuns(ctx, certID)
	if len(runs) != 1 || runs[0].Status != db.RunStatusError {
		t.Fatalf("runs = %+v, want one errored run", runs)
	}
	events, _ := is.Store.ListRunEvents(ctx, runs[0].ID)
	var sawError bool
	for _, e := range events {
		if e.Level == db.LevelError {
			sawError = true
		}
	}
	if !sawError {
		t.Error("no error-level event recorded on the failure path")
	}

	// 清理走 defer，失败路径也要执行。
	if got := caSrv.DNS.Values("_acme-challenge.example.com"); len(got) != 0 {
		t.Errorf("challenge records left behind after failure: %v", got)
	}
}

func TestIssueIncrementsAttempt(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "auto"); err != nil {
		t.Fatal(err)
	}

	runs, _ := is.Store.ListRuns(ctx, certID)
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(runs))
	}
	if runs[0].Attempt != 2 || runs[1].Attempt != 1 {
		t.Errorf("attempts = [%d %d], want [2 1]", runs[0].Attempt, runs[1].Attempt)
	}
}

func TestIssueMissingCertificate(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	if err := is.Issue(context.Background(), 999, "manual"); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("Issue on a missing certificate = %v, want ErrNotFound", err)
	}
}

func TestRedactConfig(t *testing.T) {
	// 时间线要能展示 provider 配置，但不能泄漏凭据。
	got := redactConfig(`{"api_token":"supersecrettoken","zone_id":"abc123"}`)
	if strings.Contains(got, "supersecrettoken") {
		t.Errorf("redactConfig = %q, still contains the token", got)
	}
	if !strings.Contains(got, "supe***") {
		t.Errorf("redactConfig = %q, want the first four characters kept", got)
	}
	if !strings.Contains(got, "abc123") {
		t.Errorf("redactConfig = %q, want non-secret fields preserved", got)
	}
}

func TestRenewalReplacesTheCertificateAndKeepsTheKey(t *testing.T) {
	// 续签就是对同一行证书再跑一次签发。证书必须真的换掉，而私钥默认
	// 保留——轮换会打断任何按公钥固定的东西（TLSA 的 SPKI selector 就得
	// 每次续期重新发布）。certbot 的默认恰好相反，所以这是有意的选择，
	// 由 RotateKey 开关提供另一种行为。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	first, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}

	if err := is.Issue(ctx, certID, "auto"); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	second, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}

	if second.Status != "issued" {
		t.Fatalf("status after renewal = %q, want issued", second.Status)
	}
	if first.KeyPEM != second.KeyPEM {
		t.Error("the private key changed although rotation was not requested")
	}
	if first.CertPEM == nil || second.CertPEM == nil || *first.CertPEM == *second.CertPEM {
		t.Error("the certificate was not replaced by the renewal")
	}
	if first.Serial == nil || second.Serial == nil || *first.Serial == *second.Serial {
		t.Errorf("serial unchanged across the renewal: %v", first.Serial)
	}
	// 新证书的私钥必须与新证书匹配，否则部署出去的是一对废物。
	assertKeyMatchesCert(t, second.KeyPEM, *second.CertPEM)
	// 叶子仍与链分离。
	if second.ChainPEM == nil || *second.CertPEM == *second.ChainPEM {
		t.Error("renewal collapsed the leaf and chain back together")
	}
}

func TestRenewalClearsFailureState(t *testing.T) {
	// 一次失败的续签会记下 retry_count/retry_after；成功后必须清零，
	// 否则退避会一直累加下去。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatal(err)
	}
	if err := is.Store.RecordRenewalFailure(ctx, certID, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := is.Store.GetCertificate(ctx, certID)
	if before.RetryCount == 0 {
		t.Fatal("the fixture did not record a failure")
	}

	if err := is.Issue(ctx, certID, "auto"); err != nil {
		t.Fatal(err)
	}
	after, _ := is.Store.GetCertificate(ctx, certID)
	if after.RetryCount != 0 || after.RetryAfter != nil {
		t.Errorf("retry state after a successful renewal = count %d, after %v; want cleared",
			after.RetryCount, after.RetryAfter)
	}
	if after.LastError != nil {
		t.Errorf("last_error = %v, want cleared", after.LastError)
	}
}

// assertKeyMatchesCert checks the stored key is the one the certificate was
// issued for.
func assertKeyMatchesCert(t *testing.T, keyPEM, certPEM string) {
	t.Helper()
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Errorf("the stored key does not match the stored certificate: %v", err)
	}
}

// seedIssuableWithProfile is seedIssuable plus a requested ACME profile.
func seedIssuableWithProfile(t *testing.T, is *Issuer, caSrv *testCA, domain, profile string) int64 {
	t.Helper()
	certID := seedIssuable(t, is, caSrv, domain, nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(`UPDATE certificates SET profile = ? WHERE id = ?`, profile, certID); err != nil {
		t.Fatal(err)
	}
	return certID
}

func certLifetimeDays(t *testing.T, is *Issuer, certID int64) float64 {
	t.Helper()
	c, err := is.Store.GetCertificate(context.Background(), certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.NotBefore == nil || c.NotAfter == nil {
		t.Fatal("the certificate has no dates")
	}
	nb, err := time.Parse(time.RFC3339, *c.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	na, err := time.Parse(time.RFC3339, *c.NotAfter)
	if err != nil {
		t.Fatal(err)
	}
	return na.Sub(nb).Hours() / 24
}

func TestProfileControlsIssuedLifetime(t *testing.T) {
	// The point of the whole change: validity_days never influenced what a
	// CA issued, but an ACME profile does. Production data had certificates
	// asking for 5 days that Let's Encrypt issued for 90.
	caSrv := newProfileTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	long := seedIssuableWithProfile(t, is, caSrv, "long.example.com", "classic")
	short := seedIssuableWithProfile(t, is, caSrv, "short.example.com", "shortlived")

	if err := is.Issue(ctx, long, "manual"); err != nil {
		t.Fatalf("issuing with the classic profile: %v", err)
	}
	if err := is.Issue(ctx, short, "manual"); err != nil {
		t.Fatalf("issuing with the shortlived profile: %v", err)
	}

	longDays := certLifetimeDays(t, is, long)
	shortDays := certLifetimeDays(t, is, short)
	t.Logf("classic = %.1f 天, shortlived = %.1f 天", longDays, shortDays)

	if longDays < 80 || longDays > 100 {
		t.Errorf("classic profile issued %.1f days, want ~90", longDays)
	}
	if shortDays > 10 {
		t.Errorf("shortlived profile issued %.1f days, want ~6", shortDays)
	}
	if shortDays >= longDays {
		t.Errorf("the profile had no effect: shortlived %.1f >= classic %.1f", shortDays, longDays)
	}
}

func TestUnknownProfileIsRejectedBeforeSending(t *testing.T) {
	// acmez checks the name against the directory's advertised profiles, so
	// a typo fails locally with a list of what is available.
	caSrv := newProfileTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuableWithProfile(t, is, caSrv, "example.com", "no-such-profile")

	err := is.Issue(ctx, certID, "manual")
	if err == nil {
		t.Fatal("Issue with an unknown profile = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Errorf("error = %v, want it to name the profile problem", err)
	}
	// The failure must still be recorded like any other.
	c, _ := is.Store.GetCertificate(ctx, certID)
	if c.Status != "error" {
		t.Errorf("status = %q, want error", c.Status)
	}
}

func seedIssuableWithLifetime(t *testing.T, is *Issuer, caSrv *testCA, domain string, days int64) int64 {
	t.Helper()
	certID := seedIssuable(t, is, caSrv, domain, nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(`UPDATE certificates SET validity_days = ? WHERE id = ?`, days, certID); err != nil {
		t.Fatal(err)
	}
	return certID
}

func TestRequestedLifetimeIsHonoured(t *testing.T) {
	// Google Trust Services accepts a lifetime through the order's notAfter
	// field, down to a day. Pebble implements the same field, so the effect
	// is verifiable without reaching a real CA.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuableWithLifetime(t, is, caSrv, "short.example.com", 7)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	got := certLifetimeDays(t, is, certID)
	t.Logf("requested 7 days, issued %.2f", got)
	// A day either side absorbs the CA's own rounding.
	if got < 6 || got > 8 {
		t.Errorf("issued lifetime = %.2f days, want about 7", got)
	}
}

func TestNoLifetimeRequestedLeavesTheCADefault(t *testing.T) {
	// validity_days = 0 must send no notAfter at all: Let's Encrypt rejects
	// any order carrying one, so a stray value would break issuance there
	// entirely.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "default.example.com", nil)
	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ValidityDays != 0 {
		t.Fatalf("a new certificate has validity_days = %d, want 0 (ask for nothing)", c.ValidityDays)
	}
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if got := certLifetimeDays(t, is, certID); got < 80 {
		t.Errorf("issued lifetime = %.1f days, want the CA's ~90 default", got)
	}
}

func TestOrderDetailDescribesTheRequest(t *testing.T) {
	tests := []struct {
		profile string
		days    int64
		want    string
	}{
		{"", 0, "Profile: (the CA's default)"},
		{"tlsserver", 0, "Profile: tlsserver"},
		{"", 7, "Profile: (the CA's default); requested lifetime: 7 day(s)"},
		{"minimal", 3, "Profile: minimal; requested lifetime: 3 day(s)"},
	}
	for _, tt := range tests {
		if got := orderDetail(tt.profile, tt.days); got != tt.want {
			t.Errorf("orderDetail(%q, %d) = %q, want %q", tt.profile, tt.days, got, tt.want)
		}
	}
}

func TestDoHSettingsAreReadPerIssuance(t *testing.T) {
	// The config center can replace the configuration while the process
	// runs. Capturing DoH settings at construction — as the wiring used to —
	// left a pushed change to dns_verification silently ineffective until
	// the next restart, while the deployer's management URL right beside it
	// was read live.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)

	var reads int
	skip := true
	is.DoH = func() DoHSettings {
		reads++
		return DoHSettings{Skip: skip}
	}

	ctx := context.Background()
	first := seedIssuable(t, is, caSrv, "one.example.com", nil)
	if err := is.Issue(ctx, first, "manual"); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	if reads == 0 {
		t.Fatal("the issuer never consulted DoH settings")
	}

	// Flip the setting without rebuilding the issuer; the next issuance
	// must see the new value.
	before := reads
	skip = false
	is.DoH = func() DoHSettings {
		reads++
		// A resolver that reports the record immediately, standing in for
		// the pushed configuration taking effect.
		return DoHSettings{Skip: false, Server: "http://127.0.0.1:1", Retries: 1, Interval: time.Millisecond}
	}
	second := seedIssuable(t, is, caSrv, "two.example.com", nil)
	err := is.Issue(ctx, second, "manual")

	if reads <= before {
		t.Error("the second issuance reused captured settings instead of re-reading them")
	}
	// The unreachable resolver must make the run fail: proof the new value
	// was actually applied rather than the old Skip:true lingering.
	if err == nil {
		t.Error("issuance succeeded with an unreachable DoH server; the old skip setting was still in force")
	}
}

func TestPerCertificateSkipBypassesTheCheck(t *testing.T) {
	// A zone our resolver cannot see — split-horizon, internal DNS — is
	// still perfectly visible to the CA. Without a per-certificate escape
	// the propagation check blocks issuance for no reason, and the only
	// alternative was disabling it for every certificate at once.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	// A resolver that can never answer. With the check on, issuance fails.
	is.DoH = func() DoHSettings {
		return DoHSettings{Server: "https://127.0.0.1:1/dns-query", Retries: 1, Interval: time.Millisecond}
	}

	blocked := seedIssuable(t, is, caSrv, "blocked.example.com", nil)
	if err := is.Issue(ctx, blocked, "manual"); err == nil {
		t.Fatal("issuance succeeded with an unreachable resolver; the check is not running")
	}

	skipped := seedIssuable(t, is, caSrv, "skipped.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET skip_dns_check = 1 WHERE id = ?`, skipped); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, skipped, "manual"); err != nil {
		t.Fatalf("issuance with the check skipped = %v, want success", err)
	}

	// The timeline has to say the check was skipped and why, so nobody
	// later mistakes a bypassed check for a passing one.
	runs, err := is.Store.ListRuns(ctx, skipped)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Type == "dns_verify" {
			found = true
			if !strings.Contains(e.Message, "skipped") {
				t.Errorf("dns_verify message = %q, want it to say the check was skipped", e.Message)
			}
			if e.Detail == nil || !strings.Contains(*e.Detail, "this certificate") {
				t.Errorf("dns_verify detail = %v, want it to name the per-certificate switch", e.Detail)
			}
		}
	}
	if !found {
		t.Error("no dns_verify event recorded")
	}
}

func TestSkippedCheckWaitsInstead(t *testing.T) {
	// Skipping the check does not mean handing the challenge over the
	// instant the record is written: without a look, something still has
	// to absorb propagation delay, and if the CA absorbs it the failure
	// arrives later and reads worse than ours would have.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	const wait = 300 * time.Millisecond
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: wait} }

	certID := seedIssuable(t, is, caSrv, "waited.example.com", nil)
	start := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if elapsed := time.Since(start); elapsed < wait {
		t.Errorf("issuance took %v, want at least the %v wait", elapsed, wait)
	}

	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var said bool
	for _, e := range events {
		if e.Type == "dns_verify" && strings.Contains(e.Message, "Waited") {
			said = true
		}
	}
	if !said {
		t.Error("the timeline does not record that it waited without checking")
	}
}

func TestSkipWaitHonoursCancellation(t *testing.T) {
	// A long blind wait must not outlive the run's context.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: time.Hour} }

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	certID := seedIssuable(t, is, caSrv, "cancelled.example.com", nil)
	start := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err == nil {
		t.Error("Issue() = nil, want the cancelled context to surface")
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Errorf("Issue() took %v; the wait ignored cancellation", elapsed)
	}
}

func TestRenewalRotatesTheKeyWhenAsked(t *testing.T) {
	// The opt-in half of the same decision: rotation limits how long a
	// leaked key stays useful, for anyone who is not pinning it.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "rotate.example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	first, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}

	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(`UPDATE certificates SET rotate_key = 1 WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "auto"); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	second, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}

	if first.KeyPEM == second.KeyPEM {
		t.Error("the key was reused although rotation was requested")
	}
	// Whichever key ends up stored has to match the certificate stored with
	// it, or what gets deployed is a useless pair.
	assertKeyMatchesCert(t, second.KeyPEM, *second.CertPEM)
}

func TestUnusableStoredKeyStopsTheRenewal(t *testing.T) {
	// Falling back to a fresh key here would silently rotate for someone
	// who explicitly asked not to — the failure they need to see.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "broken.example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET key_pem = 'not a key' WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}

	if err := is.Issue(ctx, certID, "auto"); err == nil {
		t.Error("renewal succeeded with an unparseable stored key; it must not quietly rotate")
	}
}
