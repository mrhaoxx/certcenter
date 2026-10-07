// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"testing"
	"time"
)

func TestRenewBeforeDaysOverridesARI(t *testing.T) {
	// A per-certificate lead time has to beat ARI, or setting it would do
	// nothing for the certificates that most need it — the ones whose CA
	// suggests renewing later than the operator is comfortable with.
	s := NewTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	certID := seedCertificate(t, s)

	// Expires in 20 days; ARI says wait another 10.
	if _, err := s.DB.Exec(`UPDATE certificates SET
		status='issued', auto_renew=1,
		not_before=?, not_after=?, renew_after=?, renew_before_days=30
		WHERE id=?`,
		now.AddDate(0, 0, -70).Format(rfc3339),
		now.AddDate(0, 0, 20).Format(rfc3339),
		now.AddDate(0, 0, 10).Format(rfc3339),
		certID); err != nil {
		t.Fatal(err)
	}

	due, err := s.DueForRenewal(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Fatalf("due = %d certificates, want 1 — 20 days left is inside the 30-day lead time", len(due))
	}
}

func TestRenewBeforeDaysNotYetReached(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	certID := seedCertificate(t, s)

	// 60 days left, lead time 30: not yet, and ARI must not drag it in.
	if _, err := s.DB.Exec(`UPDATE certificates SET
		status='issued', auto_renew=1,
		not_before=?, not_after=?, renew_after=?, renew_before_days=30
		WHERE id=?`,
		now.AddDate(0, 0, -30).Format(rfc3339),
		now.AddDate(0, 0, 60).Format(rfc3339),
		now.AddDate(0, 0, -1).Format(rfc3339), // ARI says renew now
		certID); err != nil {
		t.Fatal(err)
	}

	due, err := s.DueForRenewal(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Errorf("due = %d, want 0 — an explicit lead time replaces ARI rather than adding to it", len(due))
	}
}

func TestZeroLeadTimeKeepsTheExistingRules(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	certID := seedCertificate(t, s)

	if _, err := s.DB.Exec(`UPDATE certificates SET
		status='issued', auto_renew=1,
		not_before=?, not_after=?, renew_after=?, renew_before_days=0
		WHERE id=?`,
		now.AddDate(0, 0, -60).Format(rfc3339),
		now.AddDate(0, 0, 30).Format(rfc3339),
		now.AddDate(0, 0, -1).Format(rfc3339),
		certID); err != nil {
		t.Fatal(err)
	}

	due, err := s.DueForRenewal(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Errorf("due = %d, want 1 — ARI still applies when no lead time is set", len(due))
	}
}
