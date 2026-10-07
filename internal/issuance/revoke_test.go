// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestRevokeAgainstTestCA(t *testing.T) {
	// Revocation is the only answer to a leaked key, and there was none.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "revoke.example.com", nil)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("issuance: %v", err)
	}

	if err := is.Revoke(ctx, certID, "keyCompromise"); err != nil {
		t.Fatalf("Revoke() = %v", err)
	}

	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "revoked" {
		t.Errorf("status = %q, want revoked", c.Status)
	}
	if revokedAt(c) == "" {
		t.Error("revoked_at was not recorded")
	}
	if c.RevocationReason != "keyCompromise" {
		t.Errorf("reason = %q, want keyCompromise", c.RevocationReason)
	}
	// Auto-renewal has to stop: renewing what was just revoked would undo
	// the decision on the next sweep.
	if c.AutoRenew {
		t.Error("auto-renewal is still on for a revoked certificate")
	}
	// The material stays so the history remains readable.
	if c.CertPEM == nil || *c.CertPEM == "" {
		t.Error("the certificate body was discarded; the record is now unreadable")
	}
}

func revokedAt(c *db.Certificate) string {
	if c.RevokedAt == nil {
		return ""
	}
	return *c.RevokedAt
}

func timeNow() time.Time { return time.Now() }

func TestRevokedCertificateIsNotRenewed(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "norenew.example.com", nil)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatal(err)
	}
	if err := is.Revoke(ctx, certID, "superseded"); err != nil {
		t.Fatal(err)
	}

	store := is.Store.(*db.SQLite)
	// Force it to look overdue in every other respect.
	if _, err := store.DB.Exec(`UPDATE certificates SET auto_renew = 1,
		not_before = datetime('now','-80 days'), not_after = datetime('now','+1 day')
		WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}
	due, err := store.DueForRenewal(ctx, timeNow())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range due {
		if c.ID == certID {
			t.Error("a revoked certificate was selected for renewal")
		}
	}
}

func TestRevokeRejectsUnknownReason(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	if err := is.Revoke(context.Background(), 1, "becauseIFeltLikeIt"); err == nil {
		t.Error("Revoke accepted an unknown reason")
	} else if !strings.Contains(err.Error(), "becauseIFeltLikeIt") {
		t.Errorf("error = %v, want it to name the bad reason", err)
	}
}

func TestRevokeNeedsAnIssuedCertificate(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "never.example.com", nil)

	if err := is.Revoke(ctx, certID, "unspecified"); err == nil {
		t.Error("Revoke succeeded for a certificate that was never issued")
	}
}
