// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
	"time"
)

// DueForRenewal returns the certificates whose renewal is due now.
//
// Three things differ deliberately from the Rust query.
//
// It selects 'error' alongside 'issued': the Rust version set
// status='error' on a failed renewal while selecting only status='issued',
// so one failure removed a certificate from automatic renewal permanently
// and it silently expired.
//
// It honours renew_after — the instant ARI told us the CA prefers — and
// only falls back to a heuristic when the CA offers no ARI.
//
// And that fallback measures the certificate's real lifetime
// (not_after − not_before) rather than the requested validity_days. A CA
// issues whatever lifetime it likes regardless of what was asked for:
// production data had certificates with validity_days=5 that Let's Encrypt
// had issued for 90 days, so the old rule renewed every four days for no
// reason.
func (s *SQLite) DueForRenewal(ctx context.Context, now time.Time) ([]Certificate, error) {
	nowStr := now.UTC().Format(rfc3339)
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+certificateColumns+` FROM certificates
		 WHERE auto_renew = 1
		   -- 'revoked' is deliberately absent: renewing a certificate
		   -- somebody just revoked would undo the decision.
		   AND status IN ('issued', 'error')
		   AND (retry_after IS NULL OR julianday(retry_after) <= julianday(?))
		   AND (
		         -- An explicit per-certificate lead time wins over both ARI
		         -- and the fraction, for a service that needs more runway
		         -- than either would give it.
		         (renew_before_days > 0 AND not_after IS NOT NULL
		          AND julianday(not_after) - julianday(?) <= renew_before_days)
		      OR (renew_before_days = 0 AND renew_after IS NOT NULL
		          AND julianday(renew_after) <= julianday(?))
		      OR (renew_before_days = 0 AND renew_after IS NULL
		          AND not_after IS NOT NULL AND not_before IS NOT NULL
		          AND julianday(not_after) - julianday(?)
		              <= (julianday(not_after) - julianday(not_before)) * 0.2)
		       )
		 ORDER BY not_after ASC`, nowStr, nowStr, nowStr, nowStr)
	if err != nil {
		return nil, fmt.Errorf("select certificates due for renewal: %w", err)
	}
	defer rows.Close()

	out := []Certificate{}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// RecordRenewalFailure applies exponential backoff so a certificate that
// cannot renew is retried later instead of either hammering the CA or —
// as in the Rust implementation — never being tried again.
func (s *SQLite) RecordRenewalFailure(ctx context.Context, id int64, now time.Time) error {
	cert, err := s.GetCertificate(ctx, id)
	if err != nil {
		return err
	}
	attempts := cert.RetryCount + 1

	// 2^attempts hours, capped at a day: quick enough to recover from a
	// transient DNS failure, slow enough not to hammer the CA.
	backoff := time.Duration(1<<min(attempts, 5)) * time.Hour
	if backoff > 24*time.Hour {
		backoff = 24 * time.Hour
	}
	retryAfter := now.Add(backoff).UTC().Format(rfc3339)

	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET retry_count = ?, retry_after = ?, updated_at = datetime('now')
		 WHERE id = ?`, attempts, retryAfter, id)
	if err != nil {
		return fmt.Errorf("record renewal failure for %d: %w", id, err)
	}
	return requireAffected(res)
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
