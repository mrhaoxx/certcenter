// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"testing"
)

func TestDNSProviderCRUD(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	id, err := s.CreateDNSProvider(ctx, DNSProvider{
		Name: "cf", Kind: "cloudflare", Config: `{"api_token":"t","zone_id":"z"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetDNSProvider(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "cf" || got.Kind != "cloudflare" {
		t.Errorf("provider = %+v", got)
	}

	newName := "cloudflare-prod"
	if err := s.UpdateDNSProvider(ctx, id, NamedUpdate{Name: &newName}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetDNSProvider(ctx, id)
	if got.Name != newName {
		t.Errorf("Name = %q, want %q", got.Name, newName)
	}
	if got.Kind != "cloudflare" {
		t.Errorf("Kind = %q, want it immutable", got.Kind)
	}

	list, err := s.ListDNSProviders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("len = %d, want 1", len(list))
	}

	if err := s.DeleteDNSProvider(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDNSProvider(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("provider still present: %v", err)
	}
}

func TestCountCertificatesUsingProviderAndAccount(t *testing.T) {
	// 删除被引用的提供商/账户时 API 要回 409，靠这两个计数判断。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	for _, id := range []int64{acctID} {
		n, err := s.CountCertificatesUsingACMEAccount(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("account in use by %d certificates, want 0", n)
		}
	}

	if _, err := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.CountCertificatesUsingDNSProvider(ctx, dnsID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("dns provider in use by %d, want 1", n)
	}
	n, err = s.CountCertificatesUsingACMEAccount(ctx, acctID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("acme account in use by %d, want 1", n)
	}
}

func TestDeployTargetCRUD(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	id, err := s.CreateDeployTarget(ctx, DeployTarget{
		Name: "web1", Kind: "ssh", Config: `{"steps":[]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeployTarget(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != "ssh" {
		t.Errorf("Kind = %q", got.Kind)
	}

	cfg := `{"steps":[{"type":"ssh_connect","name":"c","config":{}}]}`
	if err := s.UpdateDeployTarget(ctx, id, NamedUpdate{Config: &cfg}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetDeployTarget(ctx, id)
	if got.Config != cfg {
		t.Errorf("Config not updated")
	}

	if err := s.DeleteDeployTarget(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDeployTarget(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

func TestSetCertificateDeployTargetsPreservesExistingBindings(t *testing.T) {
	// Rust 版每次更新都把整组绑定删掉重建，部署历史与事件全被孤儿化。
	// 这里必须做增量：保留仍在集合里的绑定。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, err := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t1, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "a", Kind: "ssh", Config: "{}"})
	t2, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "b", Kind: "webhook", Config: "{}"})
	t3, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "c", Kind: "webhook", Config: "{}"})

	if err := s.SetCertificateDeployTargets(ctx, certID, []int64{t1, t2}); err != nil {
		t.Fatal(err)
	}
	deployments, err := s.ListDeployments(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments) != 2 {
		t.Fatalf("len = %d, want 2", len(deployments))
	}

	// 给 t1 的绑定记录一次成功，然后把集合改成 {t1, t3}。
	var t1Deployment int64
	for _, d := range deployments {
		if d.DeployTargetID == t1 {
			t1Deployment = d.ID
		}
	}
	if err := s.UpdateDeploymentResult(ctx, t1Deployment, "success", ""); err != nil {
		t.Fatal(err)
	}

	if err := s.SetCertificateDeployTargets(ctx, certID, []int64{t1, t3}); err != nil {
		t.Fatal(err)
	}
	deployments, _ = s.ListDeployments(ctx, certID)
	if len(deployments) != 2 {
		t.Fatalf("len = %d, want 2", len(deployments))
	}

	var kept *Deployment
	for i := range deployments {
		if deployments[i].DeployTargetID == t1 {
			kept = &deployments[i]
		}
	}
	if kept == nil {
		t.Fatal("the t1 binding disappeared")
	}
	if kept.ID != t1Deployment {
		t.Errorf("t1 binding id = %d, want %d preserved", kept.ID, t1Deployment)
	}
	if kept.Status != "success" || kept.LastDeployedAt == nil {
		t.Errorf("t1 binding lost its history: %+v", kept)
	}
}

func TestListDeploymentsJoinsTargetDetails(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	targetID, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "web1", Kind: "ssh", Config: "{}"})
	if err := s.SetCertificateDeployTargets(ctx, certID, []int64{targetID}); err != nil {
		t.Fatal(err)
	}

	deployments, err := s.ListDeployments(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments) != 1 {
		t.Fatalf("len = %d", len(deployments))
	}
	d := deployments[0]
	if d.TargetName != "web1" || d.TargetKind != "ssh" {
		t.Errorf("deployment = %+v, want the target's name and kind joined in", d)
	}
	if d.Status != "pending" {
		t.Errorf("Status = %q, want pending", d.Status)
	}
}

func TestUpdateDeploymentResult(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	targetID, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "t", Kind: "ssh", Config: "{}"})
	s.SetCertificateDeployTargets(ctx, certID, []int64{targetID})
	deployments, _ := s.ListDeployments(ctx, certID)
	depID := deployments[0].ID

	if err := s.UpdateDeploymentResult(ctx, depID, "failed", "connection refused"); err != nil {
		t.Fatal(err)
	}
	deployments, _ = s.ListDeployments(ctx, certID)
	if deployments[0].Status != "failed" {
		t.Errorf("Status = %q", deployments[0].Status)
	}
	if deployments[0].LastError == nil || *deployments[0].LastError != "connection refused" {
		t.Errorf("LastError = %v", deployments[0].LastError)
	}
	if deployments[0].LastDeployedAt != nil {
		t.Error("LastDeployedAt set on a failure, want it only on success")
	}

	if err := s.UpdateDeploymentResult(ctx, depID, "success", ""); err != nil {
		t.Fatal(err)
	}
	deployments, _ = s.ListDeployments(ctx, certID)
	if deployments[0].LastDeployedAt == nil {
		t.Error("LastDeployedAt not set on success")
	}
	if deployments[0].LastError != nil {
		t.Errorf("LastError = %v, want it cleared on success", deployments[0].LastError)
	}
}

func TestDeploymentsCascadeWithTarget(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	targetID, _ := s.CreateDeployTarget(ctx, DeployTarget{Name: "t", Kind: "ssh", Config: "{}"})
	s.SetCertificateDeployTargets(ctx, certID, []int64{targetID})

	n, err := s.CountDeploymentsUsingTarget(ctx, targetID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("target in use by %d deployments, want 1", n)
	}
}
