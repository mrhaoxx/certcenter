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

// setSkipWait writes the per-certificate override; nil means inherit.
func setSkipWait(t *testing.T, is *Issuer, certID int64, seconds *int64) {
	t.Helper()
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET skip_dns_check = 1, skip_dns_wait_seconds = ? WHERE id = ?`,
		seconds, certID); err != nil {
		t.Fatal(err)
	}
}

func TestPerCertificateWaitOverridesTheGlobalOne(t *testing.T) {
	// The column, the API and the form all carried this value while
	// issuance still read the global one, so a certificate configured for
	// 60s waited the global 30s and the timeline said so.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: time.Hour} }

	override := int64(0) // seconds; zero keeps the test quick and is itself meaningful
	certID := seedIssuable(t, is, caSrv, "override.example.com", nil)
	setSkipWait(t, is, certID, &override)

	start := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	// An hour-long global wait must not apply.
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("issuance took %v; the global wait was used instead of the override", elapsed)
	}
}

func TestPerCertificateWaitIsActuallyWaited(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	// Global says do not wait; the certificate asks for one.
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: 0} }

	override := int64(1)
	certID := seedIssuable(t, is, caSrv, "waits.example.com", nil)
	setSkipWait(t, is, certID, &override)

	start := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("issuance took %v; the per-certificate wait was ignored", elapsed)
	}

	// The timeline has to name which switch chose the duration, or a
	// mismatch like the one this fixes is invisible.
	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, e := range events {
		if e.Type == "dns_verify" && e.Detail != nil &&
			strings.Contains(*e.Detail, "set for this certificate") {
			named = true
		}
	}
	if !named {
		t.Error("the timeline does not say the wait came from the certificate")
	}
}

func TestNilWaitInheritsTheGlobalOne(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: time.Second} }

	certID := seedIssuable(t, is, caSrv, "inherit.example.com", nil)
	setSkipWait(t, is, certID, nil)

	start := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	if elapsed := time.Since(start); elapsed < time.Second {
		t.Errorf("issuance took %v; the global wait was not inherited", elapsed)
	}
}

func TestNoWaitWhenNothingWasWritten(t *testing.T) {
	// Every authorization already valid means no challenge is presented
	// and nothing is written, so there is no propagation to wait for. The
	// skip branch waited regardless, adding the whole delay to an issuance
	// that did no DNS work at all.
	//
	// The wait is short on purpose: the first issuance does write records,
	// so it genuinely serves the delay, and a long one here would hang the
	// test on the very behaviour being checked.
	// Real CAs reuse a valid authorization for weeks — Let's Encrypt for
	// thirty days — which is exactly when this bug shows. Pebble reuses
	// only when told to.
	t.Setenv("PEBBLE_AUTHZREUSE", "100")

	const wait = 2 * time.Second
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true, SkipWait: wait} }

	certID := seedIssuable(t, is, caSrv, "reused.example.com", nil)

	firstStart := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	if elapsed := time.Since(firstStart); elapsed < wait {
		t.Fatalf("the first issuance took %v; it should have served the %v wait "+
			"after writing records", elapsed, wait)
	}

	// The second reuses the authorization, writes nothing, and must not
	// serve the wait.
	secondStart := time.Now()
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("second issuance: %v", err)
	}
	if elapsed := time.Since(secondStart); elapsed >= wait {
		t.Errorf("the second issuance took %v; it waited despite writing nothing", elapsed)
	}

	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Type == "dns_verify" && strings.Contains(e.Message, "waiting") {
			t.Errorf("the newest run says it waited: %q", e.Message)
		}
	}
}
