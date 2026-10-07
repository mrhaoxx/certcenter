// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// These cover the last step of each option's path: the stored value
// reaching the code that acts on it.
//
// A mutation check — cutting each cert.<Field> out of issuance and
// re-running the suite — found three that no test noticed. That is
// exactly how skip_dns_wait_seconds shipped with a column, an endpoint and
// a form while issuance still read the global value. Testing the helper in
// isolation says nothing about whether anything calls it with the right
// argument.

func TestNotBeforeDaysReachesTheOrder(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "notbefore.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET not_before_days = 2 WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := time.Parse(time.RFC3339, *c.NotBefore)
	if err != nil {
		t.Fatal(err)
	}
	// Pebble honours a requested notBefore, so a two-day offset must show
	// up in the issued certificate rather than starting now.
	if delta := time.Until(nb); delta < 24*time.Hour {
		t.Errorf("notBefore is %v away, want about two days — the request never reached the order", delta)
	}
}

func TestExtendedKeyUsageReachesTheCSR(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "eku.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET extended_key_usage = 'serverAuth' WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	// The CA decides the certificate's own EKU, so what is verifiable here
	// is that the stored value reached the CSR. The timeline records it,
	// which is also what an operator needs to confirm the request.
	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var reported bool
	for _, e := range events {
		if e.Type == "generate_csr" && e.Detail != nil &&
			strings.Contains(*e.Detail, "Extended key usage: serverAuth") {
			reported = true
		}
	}
	if !reported {
		t.Error("the timeline does not report the requested extended key usage; " +
			"the stored value may never have reached the CSR")
	}
}

func TestPreferredChainSelectsByIssuer(t *testing.T) {
	// Pebble offers one chain, so the selection is exercised directly:
	// what matters is that a named issuer wins and an unmatched one falls
	// back rather than failing the issuance.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "chain.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET preferred_chain = 'No Such Issuer' WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v; an unmatched preference must not fail the issuance", err)
	}

	// And the timeline has to say the preference went unmatched, or an
	// operator would believe they got the chain they asked for.
	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var explained bool
	for _, e := range events {
		if e.Type == "download_cert" && e.Detail != nil &&
			strings.Contains(*e.Detail, "none matched preferred issuer") {
			explained = true
		}
	}
	if !explained {
		t.Error("the timeline does not report that the preferred chain was unavailable")
	}

	// The matching path: ask for the issuer the CA actually used.
	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(*c.CertPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(`UPDATE certificates SET preferred_chain = ? WHERE id = ?`,
		leaf.Issuer.CommonName, certID); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() with a matching preference = %v", err)
	}
	runs, _ = is.Store.ListRuns(ctx, certID)
	events, _ = is.Store.ListRunEvents(ctx, runs[0].ID)
	var matched bool
	for _, e := range events {
		if e.Type == "download_cert" && e.Detail != nil &&
			strings.Contains(*e.Detail, "matched preferred issuer") &&
			!strings.Contains(*e.Detail, "none matched") {
			matched = true
		}
	}
	if !matched {
		t.Error("a preference naming the actual issuer was not reported as matched")
	}
}
