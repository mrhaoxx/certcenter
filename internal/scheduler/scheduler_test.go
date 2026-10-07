// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

type fakeIssuer struct {
	mu     sync.Mutex
	issued []int64
	err    error
}

func (f *fakeIssuer) Issue(_ context.Context, certID int64, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, certID)
	return f.err
}

func (f *fakeIssuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.issued)
}

type fakeDeployer struct {
	mu       sync.Mutex
	deployed []int64
}

func (f *fakeDeployer) DeployCertificate(_ context.Context, certID int64, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deployed = append(f.deployed, certID)
	return nil
}

// fixture creates a store and returns it with a helper that adds a
// certificate in a given state.
func fixture(t *testing.T) (*db.SQLite, func(t *testing.T, status string, notAfter time.Time, opts ...certOpt) int64) {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	ctx := context.Background()

	acctID, err := store.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "le", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := store.CreateDNSProvider(ctx, db.DNSProvider{Name: "cf", Kind: "cloudflare", Config: "{}"})
	if err != nil {
		t.Fatal(err)
	}

	n := 0
	return store, func(t *testing.T, status string, notAfter time.Time, opts ...certOpt) int64 {
		t.Helper()
		n++
		settings := certSettings{autoRenew: true, validityDays: 90}
		for _, o := range opts {
			o(&settings)
		}
		id, err := store.CreateCertificate(ctx, db.Certificate{
			Domain:        fmt.Sprintf("host%d.example.com", n),
			ACMEAccountID: acctID, DNSProviderID: dnsID,
			ValidityDays: settings.validityDays, AutoRenew: settings.autoRenew,
		})
		if err != nil {
			t.Fatal(err)
		}
		issued := db.IssuedCertificate{
			CertPEM: "L", ChainPEM: "I", KeyPEM: "K", Serial: "01",
			NotBefore: notAfter.Add(-time.Duration(settings.validityDays) * 24 * time.Hour),
			NotAfter:  notAfter,
		}
		if settings.renewAfter != nil {
			issued.RenewAfter = settings.renewAfter
		}
		if err := store.SaveIssuedCertificate(ctx, id, issued); err != nil {
			t.Fatal(err)
		}
		if status != "issued" {
			if err := store.UpdateCertificateStatus(ctx, id, status, "previous failure"); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
}

type certSettings struct {
	autoRenew    bool
	validityDays int64
	renewAfter   *time.Time
}

type certOpt func(*certSettings)

func withAutoRenew(v bool) certOpt { return func(c *certSettings) { c.autoRenew = v } }
func withRenewAfter(t time.Time) certOpt {
	return func(c *certSettings) { c.renewAfter = &t }
}

func TestDueForRenewalSelection(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()

	fresh := add(t, "issued", now.Add(80*24*time.Hour))
	dueSoon := add(t, "issued", now.Add(5*24*time.Hour))
	alreadyExpired := add(t, "issued", now.Add(-24*time.Hour))
	// 关键回归：Rust 版续期失败会置 status='error'，而它的筛选只看
	// status='issued'，于是这张证书再也不会被自动扫到，直到静默过期。
	previouslyFailed := add(t, "error", now.Add(5*24*time.Hour))
	manual := add(t, "issued", now.Add(5*24*time.Hour), withAutoRenew(false))

	due, err := store.DueForRenewal(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, c := range due {
		got[c.ID] = true
	}

	for _, want := range []struct {
		id       int64
		selected bool
		why      string
	}{
		{fresh, false, "还早，不该续"},
		{dueSoon, true, "剩余寿命已进入最后 20%"},
		{alreadyExpired, true, "已过期，仍要尝试续"},
		{previouslyFailed, true, "上次失败过的证书必须还能被扫到"},
		{manual, false, "关闭了自动续期"},
	} {
		if got[want.id] != want.selected {
			t.Errorf("certificate %d selected=%v, want %v (%s)",
				want.id, got[want.id], want.selected, want.why)
		}
	}
}

func TestDueForRenewalHonoursARIWindow(t *testing.T) {
	// 有 ARI 时以 CA 给的时刻为准，而不是"剩余 20%"的经验规则。
	store, add := fixture(t)
	now := time.Now()

	// 还很新，但 CA 说现在就该续（例如大规模吊销事件）。
	ariNow := add(t, "issued", now.Add(80*24*time.Hour), withRenewAfter(now.Add(-time.Hour)))
	// 快到期了，但 CA 说再等等。
	ariLater := add(t, "issued", now.Add(5*24*time.Hour), withRenewAfter(now.Add(48*time.Hour)))

	due, err := store.DueForRenewal(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[int64]bool{}
	for _, c := range due {
		got[c.ID] = true
	}
	if !got[ariNow] {
		t.Error("a certificate whose ARI window has opened was not selected")
	}
	if got[ariLater] {
		t.Error("a certificate whose ARI window is still ahead was selected anyway")
	}
}

func TestRetryBackoffDelaysTheNextAttempt(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()
	id := add(t, "issued", now.Add(5*24*time.Hour))

	if err := store.RecordRenewalFailure(context.Background(), id, now); err != nil {
		t.Fatal(err)
	}
	cert, err := store.GetCertificate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.RetryCount != 1 {
		t.Errorf("RetryCount = %d, want 1", cert.RetryCount)
	}
	if cert.RetryAfter == nil {
		t.Fatal("RetryAfter not set")
	}

	// 退避期内不再被选中。
	due, err := store.DueForRenewal(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range due {
		if c.ID == id {
			t.Error("the certificate was selected again during its backoff window")
		}
	}

	// 退避期过后重新可选——这正是 Rust 版永远做不到的。
	due, err = store.DueForRenewal(context.Background(), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range due {
		if c.ID == id {
			found = true
		}
	}
	if !found {
		t.Error("the certificate was not selected again after its backoff elapsed")
	}
}

func TestBackoffIsCapped(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()
	id := add(t, "issued", now.Add(5*24*time.Hour))
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		if err := store.RecordRenewalFailure(ctx, id, now); err != nil {
			t.Fatal(err)
		}
	}
	cert, _ := store.GetCertificate(ctx, id)
	retryAfter, err := time.Parse(time.RFC3339, *cert.RetryAfter)
	if err != nil {
		t.Fatal(err)
	}
	if delay := retryAfter.Sub(now); delay > 25*time.Hour {
		t.Errorf("backoff = %v, want it capped near 24h so a certificate is never abandoned", delay)
	}
}

func TestSweepRenewsAndDeploys(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()
	id := add(t, "issued", now.Add(5*24*time.Hour))

	issuer := &fakeIssuer{}
	deployer := &fakeDeployer{}
	s := &Scheduler{Store: store, Issuer: issuer, Deployer: deployer, Now: func() time.Time { return now }}

	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if issuer.count() != 1 || issuer.issued[0] != id {
		t.Errorf("issued = %v, want [%d]", issuer.issued, id)
	}
	// 续了却没人装等于没续。
	if len(deployer.deployed) != 1 || deployer.deployed[0] != id {
		t.Errorf("deployed = %v, want [%d]", deployer.deployed, id)
	}

	logs, err := store.ListLogs(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Action != "renewed" {
		t.Errorf("logs = %+v, want a renewed entry", logs)
	}
}

func TestSweepRecordsFailureAndBacksOff(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()
	id := add(t, "issued", now.Add(5*24*time.Hour))

	issuer := &fakeIssuer{err: fmt.Errorf("DNS propagation timed out")}
	s := &Scheduler{Store: store, Issuer: issuer, Now: func() time.Time { return now }}

	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	cert, err := store.GetCertificate(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if cert.RetryCount != 1 || cert.RetryAfter == nil {
		t.Errorf("certificate = %+v, want a recorded backoff", cert)
	}

	logs, _ := store.ListLogs(context.Background(), 10, 0)
	if len(logs) == 0 || logs[0].Action != "renew_failed" {
		t.Errorf("logs = %+v, want a renew_failed entry", logs)
	}
}

func TestSweepIsBounded(t *testing.T) {
	// 并发有上限，一台卡住的 DNS API 不会拖垮整批。
	store, add := fixture(t)
	now := time.Now()
	for i := 0; i < 10; i++ {
		add(t, "issued", now.Add(5*24*time.Hour))
	}

	var mu sync.Mutex
	var inFlight, peak int
	issuer := &countingIssuer{onStart: func() {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
	}, onEnd: func() {
		mu.Lock()
		inFlight--
		mu.Unlock()
	}}

	s := &Scheduler{Store: store, Issuer: issuer, Now: func() time.Time { return now }}
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if peak > MaxConcurrent {
		t.Errorf("peak concurrency = %d, want at most %d", peak, MaxConcurrent)
	}
	if issuer.count() != 10 {
		t.Errorf("issued %d certificates, want all 10", issuer.count())
	}
}

type countingIssuer struct {
	mu      sync.Mutex
	n       int
	onStart func()
	onEnd   func()
}

func (c *countingIssuer) Issue(context.Context, int64, string) error {
	c.onStart()
	time.Sleep(5 * time.Millisecond)
	c.onEnd()
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func (c *countingIssuer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestSweepWithNothingDue(t *testing.T) {
	store, add := fixture(t)
	now := time.Now()
	add(t, "issued", now.Add(80*24*time.Hour))

	issuer := &fakeIssuer{}
	s := &Scheduler{Store: store, Issuer: issuer, Now: func() time.Time { return now }}
	if err := s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if issuer.count() != 0 {
		t.Errorf("issued %d certificates, want none", issuer.count())
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	store, _ := fixture(t)
	s := &Scheduler{Store: store, Issuer: &fakeIssuer{}}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run did not return after its context was cancelled")
	}
}
