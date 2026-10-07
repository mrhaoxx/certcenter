// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"testing"
)

// newPendingCert 建一张待签发的证书，返回其 id。
func newPendingCert(t *testing.T, s *SQLite) int64 {
	t.Helper()
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestStartRunAssignsIncrementingAttempt(t *testing.T) {
	// 同一张证书反复签发时 attempt 必须自增，UI 才能按次折叠时间线。
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)

	for want := int64(1); want <= 3; want++ {
		run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
		if err != nil {
			t.Fatal(err)
		}
		if run.Attempt != want {
			t.Errorf("attempt = %d, want %d", run.Attempt, want)
		}
		if run.Status != RunStatusRunning {
			t.Errorf("status = %q, want %q", run.Status, RunStatusRunning)
		}
	}
}

func TestStartRunNumbersDeploymentsSeparately(t *testing.T) {
	// 签发的 attempt 与每个部署目标的 attempt 各自独立计数。
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)

	res, err := s.DB.Exec(`INSERT INTO deploy_targets (name, kind, config)
	                       VALUES ('t','ssh','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	targetID, _ := res.LastInsertId()
	res, err = s.DB.Exec(`INSERT INTO deployments (certificate_id, deploy_target_id)
	                      VALUES (?, ?)`, certID, targetID)
	if err != nil {
		t.Fatal(err)
	}
	depID, _ := res.LastInsertId()

	issue, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := s.StartRun(ctx, RunKindDeploy, certID, &depID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if issue.Attempt != 1 || deploy.Attempt != 1 {
		t.Errorf("attempts = issue %d, deploy %d; want both 1", issue.Attempt, deploy.Attempt)
	}
	deploy2, err := s.StartRun(ctx, RunKindDeploy, certID, &depID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if deploy2.Attempt != 2 {
		t.Errorf("second deploy attempt = %d, want 2", deploy2.Attempt)
	}
}

func TestAppendEventSequencesMonotonically(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)
	run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}

	detail := "Domains: example.com"
	for _, e := range []Event{
		{Type: "start", Message: "Starting issuance", Detail: &detail, Level: LevelInfo},
		{Type: "acme_connect", Message: "Connected", Level: LevelSuccess},
		{Type: "complete", Message: "Issued", Level: LevelSuccess},
	} {
		if err := s.AppendEvent(ctx, run.ID, e); err != nil {
			t.Fatal(err)
		}
	}

	events, err := s.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}
	if events[0].Type != "start" {
		t.Errorf("events[0].Type = %q, want start (ascending order)", events[0].Type)
	}
	if events[0].Detail == nil || *events[0].Detail != detail {
		t.Errorf("events[0].Detail = %v, want %q", events[0].Detail, detail)
	}
	if events[1].Detail != nil {
		t.Errorf("events[1].Detail = %v, want nil", events[1].Detail)
	}
	if events[0].At == "" {
		t.Error("At not populated by the DB default")
	}
}

func TestAppendEventDefaultsLevel(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)
	run, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "auto")

	if err := s.AppendEvent(ctx, run.ID, Event{Type: "t", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}
	if events[0].Level != LevelInfo {
		t.Errorf("level = %q, want %q", events[0].Level, LevelInfo)
	}
}

func TestFinishRun(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)

	tests := []struct {
		name, status, errMsg string
		wantErrStored        bool
	}{
		{"成功收尾", RunStatusSuccess, "", false},
		{"失败收尾带错误", RunStatusError, "DNS timed out", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.FinishRun(ctx, run.ID, tt.status, tt.errMsg); err != nil {
				t.Fatal(err)
			}
			runs, err := s.ListRuns(ctx, certID)
			if err != nil {
				t.Fatal(err)
			}
			got := runs[0] // 最新在前
			if got.Status != tt.status {
				t.Errorf("Status = %q, want %q", got.Status, tt.status)
			}
			if got.FinishedAt == nil {
				t.Error("FinishedAt is nil, want it set")
			}
			if tt.wantErrStored && (got.Error == nil || *got.Error != tt.errMsg) {
				t.Errorf("Error = %v, want %q", got.Error, tt.errMsg)
			}
			if !tt.wantErrStored && got.Error != nil {
				t.Errorf("Error = %v, want nil", got.Error)
			}
		})
	}
}

func TestListRunsNewestFirst(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)
	first, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	second, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "auto")

	runs, err := s.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("len = %d, want 2", len(runs))
	}
	if runs[0].ID != second.ID || runs[1].ID != first.ID {
		t.Errorf("order = [%d %d], want [%d %d] (newest first)",
			runs[0].ID, runs[1].ID, second.ID, first.ID)
	}
	if runs[0].Trigger != "auto" {
		t.Errorf("Trigger = %q, want auto", runs[0].Trigger)
	}
}

func TestEventsCascadeWithCertificate(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	certID := newPendingCert(t, s)
	run, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err := s.AppendEvent(ctx, run.ID, Event{Type: "t", Message: "m"}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteCertificate(ctx, certID); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"runs", "events"} {
		var n int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s left %d rows after deleting the certificate, want 0", table, n)
		}
	}
}

func TestFinishRunMissing(t *testing.T) {
	s := NewTestDB(t)
	if err := s.FinishRun(context.Background(), 999, RunStatusSuccess, ""); err == nil {
		t.Error("FinishRun on a missing run = nil error, want failure")
	}
}
