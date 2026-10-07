// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"strings"
	"testing"
)

func TestReapOrphanedRuns(t *testing.T) {
	// A run is only "running" while a goroutine drives it, so one found
	// that way at startup belonged to a process that is gone. Left alone
	// it stays open forever and its certificate sits in "pending", which
	// the renewal sweep skips — so nothing ever retries it.
	s := NewTestDB(t)
	ctx := context.Background()
	certID := seedCertificate(t, s)

	if _, err := s.DB.Exec(`UPDATE certificates SET status='pending' WHERE id=?`, certID); err != nil {
		t.Fatal(err)
	}
	run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}

	n, err := s.ReapOrphanedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reaped %d runs, want 1", n)
	}

	var status, errMsg string
	if err := s.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM runs WHERE id=?`, run.ID).
		Scan(&status, &errMsg); err != nil {
		t.Fatal(err)
	}
	if status != RunStatusError {
		t.Errorf("run status = %q, want %q", status, RunStatusError)
	}
	if !strings.Contains(errMsg, "restarted") {
		t.Errorf("run error = %q, want it to explain the restart", errMsg)
	}

	// The certificate has to leave "pending", or the sweep keeps ignoring it.
	c, err := s.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "error" {
		t.Errorf("certificate status = %q, want error so a retry can act on it", c.Status)
	}

	// And the timeline says so, which is where an operator looks first.
	events, err := s.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	var explained bool
	for _, e := range events {
		if e.Type == "interrupted" {
			explained = true
		}
	}
	if !explained {
		t.Error("no event records the interruption")
	}
}

func TestReapLeavesFinishedRunsAlone(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := seedCertificate(t, s)

	run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, run.ID, RunStatusSuccess, ""); err != nil {
		t.Fatal(err)
	}

	n, err := s.ReapOrphanedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("reaped %d, want 0 — a finished run is not orphaned", n)
	}
}

func TestReapDoesNotUndoASucceededCertificate(t *testing.T) {
	// A certificate that reached "issued" between the crash and the
	// restart must not be dragged back to an error state by its stale run.
	s := NewTestDB(t)
	ctx := context.Background()
	certID := seedCertificate(t, s)

	if _, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE certificates SET status='issued' WHERE id=?`, certID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ReapOrphanedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "issued" {
		t.Errorf("certificate status = %q, want issued left alone", c.Status)
	}
}

func TestReapIsIdempotent(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := seedCertificate(t, s)
	if _, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ReapOrphanedRuns(ctx); err != nil {
		t.Fatal(err)
	}
	n, err := s.ReapOrphanedRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second reap found %d runs, want 0", n)
	}
}
