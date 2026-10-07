// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
)

// RunStatusCancelled marks a run stopped on purpose. It is distinct from
// error so a deliberate stop does not feed the retry backoff, and so the
// timeline reads as a decision rather than a fault.
const RunStatusCancelled = "cancelled"

// ReapOrphanedRuns closes runs left open by a process that died.
//
// A run is only ever "running" while a goroutine is driving it, so any
// still marked that way at startup belonged to the previous process.
// Nothing was reconciling them, which left the run open forever and its
// certificate stuck in "pending" — a state the renewal sweep ignores, so
// it would never be retried and never expire into being noticed.
//
// The ACME exchange cannot be resumed: the order and challenge state lived
// in memory. The honest repair is to record what happened and return the
// certificate to a state a retry can act on.
func (s *SQLite) ReapOrphanedRuns(ctx context.Context) (int, error) {
	const reason = "interrupted: the service restarted while this run was in progress"

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	rows, err := tx.QueryContext(ctx,
		`SELECT id, certificate_id, kind FROM runs WHERE status = ?`, RunStatusRunning)
	if err != nil {
		return 0, fmt.Errorf("find orphaned runs: %w", err)
	}
	type orphan struct {
		id     int64
		certID int64
		kind   string
	}
	var orphans []orphan
	for rows.Next() {
		var o orphan
		if err := rows.Scan(&o.id, &o.certID, &o.kind); err != nil {
			rows.Close()
			return 0, err
		}
		orphans = append(orphans, o)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, o := range orphans {
		if _, err := tx.ExecContext(ctx,
			`UPDATE runs SET status = ?, error = ?, finished_at = datetime('now') WHERE id = ?`,
			RunStatusError, reason, o.id); err != nil {
			return 0, err
		}
		// The timeline is what an operator reads first, so the reason goes
		// there too rather than only in the run's error column.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO events (run_id, seq, type, message, level)
			 VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?),
			         'interrupted', ?, ?)`,
			o.id, o.id, reason, LevelError); err != nil {
			return 0, err
		}

		if o.kind == RunKindIssue {
			// Only a certificate still waiting on this run is moved. One
			// that reached "issued" between the crash and now must not be
			// dragged back to an error state.
			if _, err := tx.ExecContext(ctx,
				`UPDATE certificates SET status = 'error', last_error = ?, updated_at = datetime('now')
				 WHERE id = ? AND status = 'pending'`, reason, o.certID); err != nil {
				return 0, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(orphans), nil
}
