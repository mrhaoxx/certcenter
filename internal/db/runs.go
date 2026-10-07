// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
)

// StartRun opens a run, numbering it one past the highest existing attempt
// for the same (certificate, kind, deployment) so the UI can group retries.
func (s *SQLite) StartRun(ctx context.Context, kind string, certID int64,
	deploymentID *int64, trigger string) (*Run, error) {

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var attempt int64
	// Scoping the counter to the deployment as well keeps issuance attempts
	// and each target's deployment attempts on their own numbering.
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(attempt), 0) + 1 FROM runs
		 WHERE certificate_id = ? AND kind = ?
		   AND ((deployment_id IS NULL AND ? IS NULL) OR deployment_id = ?)`,
		certID, kind, deploymentID, deploymentID).Scan(&attempt)
	if err != nil {
		return nil, fmt.Errorf("compute run attempt: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO runs (kind, certificate_id, deployment_id, attempt, trigger, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		kind, certID, deploymentID, attempt, trigger, RunStatusRunning)
	if err != nil {
		return nil, fmt.Errorf("start run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Run{
		ID: id, Kind: kind, CertificateID: certID, DeploymentID: deploymentID,
		Attempt: attempt, Trigger: trigger, Status: RunStatusRunning,
	}, nil
}

func (s *SQLite) FinishRun(ctx context.Context, runID int64, status, errMsg string) error {
	var errValue any
	if errMsg != "" {
		errValue = errMsg
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE runs SET status = ?, error = ?, finished_at = datetime('now') WHERE id = ?`,
		status, errValue, runID)
	if err != nil {
		return fmt.Errorf("finish run %d: %w", runID, err)
	}
	return requireAffected(res)
}

// AppendEvent adds a timeline entry, assigning the next sequence number
// within the run.
func (s *SQLite) AppendEvent(ctx context.Context, runID int64, e Event) error {
	level := e.Level
	if level == "" {
		level = LevelInfo
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO events (run_id, seq, type, message, detail, level)
		 VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?), ?, ?, ?, ?)`,
		runID, runID, e.Type, e.Message, e.Detail, level)
	if err != nil {
		return fmt.Errorf("append event to run %d: %w", runID, err)
	}
	return nil
}

const runColumns = `id, kind, certificate_id, deployment_id, attempt, trigger,
	status, error, started_at, finished_at`

func (s *SQLite) ListRuns(ctx context.Context, certID int64) ([]Run, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+runColumns+` FROM runs WHERE certificate_id = ? ORDER BY id DESC`, certID)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()

	out := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.Kind, &r.CertificateID, &r.DeploymentID,
			&r.Attempt, &r.Trigger, &r.Status, &r.Error, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) ListRunEvents(ctx context.Context, runID int64) ([]Event, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, run_id, seq, type, message, detail, level, at
		 FROM events WHERE run_id = ? ORDER BY seq ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("list run events: %w", err)
	}
	defer rows.Close()

	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.RunID, &e.Seq, &e.Type, &e.Message,
			&e.Detail, &e.Level, &e.At); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
