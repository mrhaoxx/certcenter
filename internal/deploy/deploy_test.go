// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// scriptedTarget returns fixed events and an optional error.
type scriptedTarget struct {
	events []Event
	err    error
	calls  int
}

func (s *scriptedTarget) Deploy(context.Context, *CertificateData) ([]Event, error) {
	s.calls++
	return s.events, s.err
}

// deployFixture builds a store with an issued certificate bound to the
// named targets, returning the certificate id and the store.
func deployFixture(t *testing.T, targetNames ...string) (*db.SQLite, int64, []int64) {
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
	dnsID, err := store.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "cf", Kind: "cloudflare", Config: "{}",
	})
	if err != nil {
		t.Fatal(err)
	}
	certID, err := store.CreateCertificate(ctx, db.Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.SaveIssuedCertificate(ctx, certID, db.IssuedCertificate{
		CertPEM: "LEAF-PEM\n", ChainPEM: "CHAIN-PEM\n", KeyPEM: "KEY-PEM\n",
		Serial: "01", NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	var targetIDs []int64
	for _, name := range targetNames {
		// 每个目标带上自己的名字作为 URL，测试里的假实现据此分派，
		// 不必给生产结构体开测试专用钩子。
		id, err := store.CreateDeployTarget(ctx, db.DeployTarget{
			Name: name, Kind: "webhook",
			Config: fmt.Sprintf(`{"url":"http://%s.invalid"}`, name),
		})
		if err != nil {
			t.Fatal(err)
		}
		targetIDs = append(targetIDs, id)
	}
	if err := store.SetCertificateDeployTargets(ctx, certID, targetIDs); err != nil {
		t.Fatal(err)
	}
	return store, certID, targetIDs
}

func TestDeployCertificateRecordsRunAndEvents(t *testing.T) {
	store, certID, _ := deployFixture(t, "web1")
	ctx := context.Background()

	target := &scriptedTarget{events: []Event{
		{Type: "upload_file", Level: LevelSuccess, Message: "Uploaded", Detail: "mode=0644"},
	}}
	d := &Deployer{
		Store: store,
		NewTarget: func(string, string, Options) (Target, error) {
			return target, nil
		},
	}

	if err := d.DeployCertificate(ctx, certID, "manual"); err != nil {
		t.Fatalf("DeployCertificate() = %v", err)
	}
	if target.calls != 1 {
		t.Errorf("target called %d times, want 1", target.calls)
	}

	runs, err := store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if runs[0].Kind != db.RunKindDeploy {
		t.Errorf("run kind = %q, want %q", runs[0].Kind, db.RunKindDeploy)
	}
	if runs[0].DeploymentID == nil {
		t.Error("a deploy run must carry its deployment id")
	}
	if runs[0].Status != db.RunStatusSuccess {
		t.Errorf("run status = %q", runs[0].Status)
	}

	events, err := store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 {
		t.Fatalf("events = %d, want the start event plus the target's", len(events))
	}
	if events[0].Type != "start" {
		t.Errorf("events[0].Type = %q, want start", events[0].Type)
	}
	var sawUpload bool
	for _, e := range events {
		if e.Type == "upload_file" && e.Detail != nil && *e.Detail == "mode=0644" {
			sawUpload = true
		}
	}
	if !sawUpload {
		t.Error("the target's events were not persisted")
	}

	deployments, _ := store.ListDeployments(ctx, certID)
	if deployments[0].Status != "success" || deployments[0].LastDeployedAt == nil {
		t.Errorf("deployment = %+v, want a recorded success", deployments[0])
	}
}

func TestDeployPersistsEventsOnFailure(t *testing.T) {
	// 失败时的时间线正是操作者要看的部分，必须落库。
	store, certID, _ := deployFixture(t, "web1")
	ctx := context.Background()

	target := &scriptedTarget{
		events: []Event{{Type: "ssh_connect", Level: LevelError, Message: "connection refused"}},
		err:    fmt.Errorf("connection refused"),
	}
	d := &Deployer{
		Store:     store,
		NewTarget: func(string, string, Options) (Target, error) { return target, nil },
	}

	if err := d.DeployCertificate(ctx, certID, "auto"); err == nil {
		t.Fatal("DeployCertificate = nil error, want the failure reported")
	}

	runs, _ := store.ListRuns(ctx, certID)
	if runs[0].Status != db.RunStatusError {
		t.Errorf("run status = %q, want error", runs[0].Status)
	}
	if runs[0].Error == nil {
		t.Error("the run did not record the error")
	}
	events, _ := store.ListRunEvents(ctx, runs[0].ID)
	var sawTargetEvent bool
	for _, e := range events {
		if e.Type == "ssh_connect" {
			sawTargetEvent = true
		}
	}
	if !sawTargetEvent {
		t.Error("the failing target's events were dropped")
	}

	deployments, _ := store.ListDeployments(ctx, certID)
	if deployments[0].Status != "failed" || deployments[0].LastError == nil {
		t.Errorf("deployment = %+v, want the failure recorded", deployments[0])
	}
}

func TestOneTargetFailureDoesNotStopTheRest(t *testing.T) {
	// 一个 CDN 凭据坏掉不该让 web 服务器继续用即将过期的证书。
	store, certID, _ := deployFixture(t, "broken", "healthy")
	ctx := context.Background()

	healthy := &scriptedTarget{events: []Event{{Type: "ok", Level: LevelSuccess, Message: "done"}}}
	broken := &scriptedTarget{err: fmt.Errorf("credentials rejected")}

	d := &Deployer{
		Store: store,
		NewTarget: func(_, config string, _ Options) (Target, error) {
			if strings.Contains(config, "broken") {
				return broken, nil
			}
			return healthy, nil
		},
	}

	err := d.DeployCertificate(ctx, certID, "manual")
	if err == nil {
		t.Fatal("DeployCertificate = nil error, want the partial failure reported")
	}
	if healthy.calls != 1 {
		t.Errorf("the healthy target was called %d times, want 1 despite the other's failure", healthy.calls)
	}
	if broken.calls != 1 {
		t.Errorf("the broken target was called %d times, want 1", broken.calls)
	}

	deployments, _ := store.ListDeployments(ctx, certID)
	var sawSuccess, sawFailure bool
	for _, dep := range deployments {
		switch dep.Status {
		case "success":
			sawSuccess = true
		case "failed":
			sawFailure = true
		}
	}
	if !sawSuccess || !sawFailure {
		t.Errorf("deployments = %+v, want one success and one failure", deployments)
	}
}

func TestDeployRefusesUnissuedCertificate(t *testing.T) {
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	acctID, _ := store.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "le", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	dnsID, _ := store.CreateDNSProvider(ctx, db.DNSProvider{Name: "cf", Kind: "cloudflare", Config: "{}"})
	certID, _ := store.CreateCertificate(ctx, db.Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})

	d := &Deployer{Store: store}
	if err := d.DeployCertificate(ctx, certID, "manual"); err == nil {
		t.Error("DeployCertificate on a pending certificate = nil error, want failure")
	}
}

func TestDeployIncrementsAttemptPerDeployment(t *testing.T) {
	store, certID, _ := deployFixture(t, "web1")
	ctx := context.Background()

	target := &scriptedTarget{}
	d := &Deployer{
		Store:     store,
		NewTarget: func(string, string, Options) (Target, error) { return target, nil },
	}
	for i := 0; i < 2; i++ {
		if err := d.DeployCertificate(ctx, certID, "manual"); err != nil {
			t.Fatal(err)
		}
	}
	runs, _ := store.ListRuns(ctx, certID)
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(runs))
	}
	if runs[0].Attempt != 2 || runs[1].Attempt != 1 {
		t.Errorf("attempts = [%d %d], want [2 1]", runs[0].Attempt, runs[1].Attempt)
	}
}
