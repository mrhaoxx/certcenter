// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// seedDeps 建出证书所依赖的账户与 DNS 提供商。
func seedDeps(t *testing.T, s *SQLite) (acctID, dnsID int64) {
	t.Helper()
	ctx := context.Background()
	var err error
	acctID, err = s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "le", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO dns_providers (name, kind, config) VALUES ('cf','cloudflare','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err = res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return acctID, dnsID
}

func TestCertificateRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	id, err := s.CreateCertificate(ctx, Certificate{
		Domain:        "example.com",
		SANs:          []string{"*.example.com"},
		ACMEAccountID: acctID,
		DNSProviderID: dnsID,
		ValidityDays:  90,
		AutoRenew:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q", got.Domain)
	}
	if len(got.SANs) != 1 || got.SANs[0] != "*.example.com" {
		t.Errorf("SANs = %v, want [*.example.com]", got.SANs)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if !got.AutoRenew {
		t.Error("AutoRenew = false, want true")
	}
}

func TestCertificateEmptySANsRoundTrip(t *testing.T) {
	// SANs 存的是 JSON 数组；空列表必须回来还是空列表而不是 nil。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "solo.example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.SANs == nil {
		t.Fatal("SANs is nil, want an empty non-nil slice")
	}
	if len(got.SANs) != 0 {
		t.Errorf("SANs = %v, want empty", got.SANs)
	}
}

func TestCertificatePrivateKeyNeverSerialized(t *testing.T) {
	raw, err := json.Marshal(Certificate{Domain: "x", KeyPEM: "SECRET-CERT-KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET-CERT-KEY") {
		t.Fatalf("marshalled certificate leaks the private key: %s", raw)
	}
}

func TestSaveIssuedCertificateStoresRealDates(t *testing.T) {
	// Rust 版把 not_before/not_after 按 validity_days 估算，而 Let's Encrypt
	// 固定签 90 天，所以 validity_days≠90 时库里就是错的——偏偏续期调度器
	// 就靠这两个值算阈值。这里必须存真实证书里的日期。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 30, AutoRenew: true, // 故意与真实 90 天不一致
	})
	if err != nil {
		t.Fatal(err)
	}

	notBefore := time.Date(2026, 7, 26, 15, 10, 17, 0, time.UTC)
	notAfter := time.Date(2026, 10, 24, 15, 10, 16, 0, time.UTC)
	renewAfter := time.Date(2026, 9, 23, 15, 10, 16, 0, time.UTC)
	err = s.SaveIssuedCertificate(ctx, id, IssuedCertificate{
		CertPEM:    "LEAF",
		ChainPEM:   "INTERMEDIATE",
		KeyPEM:     "KEY",
		Serial:     "2639836FB19994A0",
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		RenewAfter: &renewAfter,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "issued" {
		t.Errorf("Status = %q, want issued", got.Status)
	}
	if got.CertPEM == nil || *got.CertPEM != "LEAF" {
		t.Errorf("CertPEM = %v, want the leaf alone", got.CertPEM)
	}
	if got.ChainPEM == nil || *got.ChainPEM != "INTERMEDIATE" {
		t.Errorf("ChainPEM = %v, want the intermediates alone", got.ChainPEM)
	}
	if got.CertPEM != nil && got.ChainPEM != nil && *got.CertPEM == *got.ChainPEM {
		t.Error("CertPEM equals ChainPEM; the leaf was never split from the chain")
	}
	if got.NotAfter == nil || !strings.HasPrefix(*got.NotAfter, "2026-10-24") {
		t.Errorf("NotAfter = %v, want the certificate's real expiry", got.NotAfter)
	}
	if got.Serial == nil || *got.Serial != "2639836FB19994A0" {
		t.Errorf("Serial = %v", got.Serial)
	}
	if got.RenewAfter == nil || !strings.HasPrefix(*got.RenewAfter, "2026-09-23") {
		t.Errorf("RenewAfter = %v, want the ARI-selected instant", got.RenewAfter)
	}
	if got.LastError != nil {
		t.Errorf("LastError = %v, want it cleared on success", got.LastError)
	}
	if got.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want it reset on success", got.RetryCount)
	}
}

func TestSaveIssuedCertificateWithoutARI(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	err := s.SaveIssuedCertificate(ctx, id, IssuedCertificate{
		CertPEM: "L", ChainPEM: "I", KeyPEM: "K", Serial: "01",
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetCertificate(ctx, id)
	if got.RenewAfter != nil {
		t.Errorf("RenewAfter = %v, want nil when the CA has no ARI", got.RenewAfter)
	}
}

func TestUpdateCertificateStatusRecordsError(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateCertificateStatus(ctx, id, "error", "DNS verification timed out"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" {
		t.Errorf("Status = %q", got.Status)
	}
	if got.LastError == nil || *got.LastError != "DNS verification timed out" {
		t.Errorf("LastError = %v", got.LastError)
	}

	// 清空错误。
	if err := s.UpdateCertificateStatus(ctx, id, "pending", ""); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetCertificate(ctx, id)
	if got.LastError != nil {
		t.Errorf("LastError = %v, want it cleared by an empty message", got.LastError)
	}
}

func TestListCertificatesFilters(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	for _, c := range []struct {
		domain string
		sans   []string
		status string
	}{
		{"alpha.example.com", nil, "issued"},
		{"beta.example.com", []string{"extra.beta.com"}, "pending"},
		{"gamma.other.net", nil, "error"},
	} {
		id, err := s.CreateCertificate(ctx, Certificate{
			Domain: c.domain, SANs: c.sans, ACMEAccountID: acctID, DNSProviderID: dnsID,
			ValidityDays: 90, AutoRenew: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.status != "pending" {
			if err := s.UpdateCertificateStatus(ctx, id, c.status, ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	tests := []struct {
		name    string
		filter  CertificateFilter
		wantLen int
	}{
		{"无过滤", CertificateFilter{}, 3},
		{"按状态", CertificateFilter{Status: "issued"}, 1},
		{"按域名子串", CertificateFilter{Search: "example.com"}, 2},
		{"搜索命中 SAN", CertificateFilter{Search: "extra.beta"}, 1},
		{"状态与搜索同时生效", CertificateFilter{Search: "example.com", Status: "pending"}, 1},
		{"无命中", CertificateFilter{Search: "nope"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := s.ListCertificates(ctx, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(list), tt.wantLen)
			}
		})
	}
}

func TestGetCertificateMissing(t *testing.T) {
	s := NewTestDB(t)
	if _, err := s.GetCertificate(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCertificate(999) = %v, want ErrNotFound", err)
	}
}

func TestDeleteCertificateMissing(t *testing.T) {
	s := NewTestDB(t)
	if err := s.DeleteCertificate(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteCertificate(999) = %v, want ErrNotFound", err)
	}
}
