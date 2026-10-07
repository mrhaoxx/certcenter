// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// The DNS provider and deploy target tables have the same shape, so their
// CRUD is generated from one pair of helpers rather than written twice.

func (s *SQLite) insertNamed(ctx context.Context, table, name, kind, config string) (int64, error) {
	if config == "" {
		config = "{}"
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO `+table+` (name, kind, config) VALUES (?, ?, ?)`, name, kind, config)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", table, err)
	}
	return res.LastInsertId()
}

func (s *SQLite) updateNamed(ctx context.Context, table string, id int64, u NamedUpdate) error {
	sets := []string{}
	args := []any{}
	if u.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *u.Name)
	}
	if u.Config != nil {
		sets = append(sets, "config = ?")
		args = append(args, *u.Config)
	}
	if len(sets) == 0 {
		var n int
		err := s.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM `+table+` WHERE id = ?`, id).Scan(&n)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	}
	sets = append(sets, "updated_at = datetime('now')")
	args = append(args, id)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE `+table+` SET `+joinComma(sets)+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("update %s %d: %w", table, id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) deleteByID(ctx context.Context, table string, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM `+table+` WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete %s %d: %w", table, id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) countWhere(ctx context.Context, query string, args ...any) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// ── DNS providers ──────────────────────────────────────────────────────

func (s *SQLite) CreateDNSProvider(ctx context.Context, p DNSProvider) (int64, error) {
	return s.insertNamed(ctx, "dns_providers", p.Name, p.Kind, p.Config)
}

func (s *SQLite) GetDNSProvider(ctx context.Context, id int64) (*DNSProvider, error) {
	var p DNSProvider
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, name, kind, config, created_at, updated_at FROM dns_providers WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Kind, &p.Config, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get dns provider %d: %w", id, err)
	}
	return &p, nil
}

func (s *SQLite) ListDNSProviders(ctx context.Context) ([]DNSProvider, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, name, kind, config, created_at, updated_at FROM dns_providers ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list dns providers: %w", err)
	}
	defer rows.Close()

	out := []DNSProvider{}
	for rows.Next() {
		var p DNSProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.Config, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateDNSProvider(ctx context.Context, id int64, u NamedUpdate) error {
	return s.updateNamed(ctx, "dns_providers", id, u)
}

func (s *SQLite) DeleteDNSProvider(ctx context.Context, id int64) error {
	return s.deleteByID(ctx, "dns_providers", id)
}

func (s *SQLite) CountCertificatesUsingDNSProvider(ctx context.Context, id int64) (int, error) {
	return s.countWhere(ctx, `SELECT count(*) FROM certificates WHERE dns_provider_id = ?`, id)
}

func (s *SQLite) CountCertificatesUsingACMEAccount(ctx context.Context, id int64) (int, error) {
	return s.countWhere(ctx, `SELECT count(*) FROM certificates WHERE acme_account_id = ?`, id)
}

// ── deploy targets ─────────────────────────────────────────────────────

func (s *SQLite) CreateDeployTarget(ctx context.Context, t DeployTarget) (int64, error) {
	return s.insertNamed(ctx, "deploy_targets", t.Name, t.Kind, t.Config)
}

func (s *SQLite) GetDeployTarget(ctx context.Context, id int64) (*DeployTarget, error) {
	var t DeployTarget
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, name, kind, config, created_at, updated_at FROM deploy_targets WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Kind, &t.Config, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get deploy target %d: %w", id, err)
	}
	return &t, nil
}

func (s *SQLite) ListDeployTargets(ctx context.Context) ([]DeployTarget, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, name, kind, config, created_at, updated_at FROM deploy_targets ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list deploy targets: %w", err)
	}
	defer rows.Close()

	out := []DeployTarget{}
	for rows.Next() {
		var t DeployTarget
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind, &t.Config, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateDeployTarget(ctx context.Context, id int64, u NamedUpdate) error {
	return s.updateNamed(ctx, "deploy_targets", id, u)
}

func (s *SQLite) DeleteDeployTarget(ctx context.Context, id int64) error {
	return s.deleteByID(ctx, "deploy_targets", id)
}

func (s *SQLite) CountDeploymentsUsingTarget(ctx context.Context, id int64) (int, error) {
	return s.countWhere(ctx, `SELECT count(*) FROM deployments WHERE deploy_target_id = ?`, id)
}

// ── deployments (certificate × target) ─────────────────────────────────

// SetCertificateDeployTargets makes the certificate's bindings exactly
// targetIDs. Existing bindings are kept rather than deleted and recreated,
// so their deployment history and run/event trail survive an unrelated edit
// — the Rust implementation deleted the whole set on every update, orphaning
// the events.
func (s *SQLite) SetCertificateDeployTargets(ctx context.Context, certID int64, targetIDs []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	wanted := map[int64]bool{}
	for _, id := range targetIDs {
		wanted[id] = true
	}

	rows, err := tx.QueryContext(ctx,
		`SELECT id, deploy_target_id FROM deployments WHERE certificate_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("read existing deployments: %w", err)
	}
	existing := map[int64]int64{} // target id → deployment id
	for rows.Next() {
		var depID, targetID int64
		if err := rows.Scan(&depID, &targetID); err != nil {
			rows.Close()
			return err
		}
		existing[targetID] = depID
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	for targetID, depID := range existing {
		if !wanted[targetID] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM deployments WHERE id = ?`, depID); err != nil {
				return fmt.Errorf("remove deployment: %w", err)
			}
		}
	}
	for targetID := range wanted {
		if _, ok := existing[targetID]; ok {
			continue
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO deployments (certificate_id, deploy_target_id) VALUES (?, ?)`,
			certID, targetID)
		if err != nil {
			return fmt.Errorf("add deployment: %w", err)
		}
	}
	return tx.Commit()
}

func (s *SQLite) ListDeployments(ctx context.Context, certID int64) ([]Deployment, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT d.id, d.certificate_id, d.deploy_target_id, t.name, t.kind,
		        d.status, d.last_deployed_at, d.last_error
		 FROM deployments d
		 JOIN deploy_targets t ON t.id = d.deploy_target_id
		 WHERE d.certificate_id = ?
		 ORDER BY d.id ASC`, certID)
	if err != nil {
		return nil, fmt.Errorf("list deployments: %w", err)
	}
	defer rows.Close()

	out := []Deployment{}
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.CertificateID, &d.DeployTargetID, &d.TargetName,
			&d.TargetKind, &d.Status, &d.LastDeployedAt, &d.LastError); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateDeploymentResult(ctx context.Context, deploymentID int64, status, lastErr string) error {
	var errValue any
	if lastErr != "" {
		errValue = lastErr
	}
	var deployedAt any
	if status == "success" {
		deployedAt = nil // set by SQL below
	}
	_ = deployedAt

	query := `UPDATE deployments SET status = ?, last_error = ?`
	args := []any{status, errValue}
	if status == "success" {
		query += `, last_deployed_at = datetime('now')`
	}
	query += ` WHERE id = ?`
	args = append(args, deploymentID)

	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update deployment %d: %w", deploymentID, err)
	}
	return requireAffected(res)
}
