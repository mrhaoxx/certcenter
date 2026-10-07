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

const acmeAccountColumns = `id, name, directory_url, email, account_url,
	private_key, validity_days, created_at, updated_at`

func scanACMEAccount(row interface{ Scan(...any) error }) (*ACMEAccount, error) {
	var a ACMEAccount
	err := row.Scan(&a.ID, &a.Name, &a.DirectoryURL, &a.Email, &a.AccountURL,
		&a.PrivateKeyPEM, &a.ValidityDays, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *SQLite) CreateACMEAccount(ctx context.Context, a ACMEAccount) (int64, error) {
	if a.ValidityDays <= 0 {
		a.ValidityDays = 90
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO acme_accounts (name, directory_url, email, account_url, private_key, validity_days)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		a.Name, a.DirectoryURL, a.Email, a.AccountURL, a.PrivateKeyPEM, a.ValidityDays)
	if err != nil {
		return 0, fmt.Errorf("create acme account: %w", err)
	}
	return res.LastInsertId()
}

func (s *SQLite) GetACMEAccount(ctx context.Context, id int64) (*ACMEAccount, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE id = ?`, id)
	a, err := scanACMEAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get acme account %d: %w", id, err)
	}
	return a, nil
}

func (s *SQLite) ListACMEAccounts(ctx context.Context) ([]ACMEAccount, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list acme accounts: %w", err)
	}
	defer rows.Close()

	out := []ACMEAccount{}
	for rows.Next() {
		a, err := scanACMEAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan acme account: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateACMEAccount(ctx context.Context, id int64, p ACMEAccountUpdate) error {
	sets := []string{}
	args := []any{}
	if p.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *p.Name)
	}
	if p.Email != nil {
		sets = append(sets, "email = ?")
		args = append(args, *p.Email)
	}
	if p.ValidityDays != nil {
		sets = append(sets, "validity_days = ?")
		args = append(args, *p.ValidityDays)
	}
	if len(sets) == 0 {
		// Nothing to change, but the caller still expects a missing id to
		// be reported.
		if _, err := s.GetACMEAccount(ctx, id); err != nil {
			return err
		}
		return nil
	}
	sets = append(sets, "updated_at = datetime('now')")
	args = append(args, id)

	res, err := s.DB.ExecContext(ctx,
		`UPDATE acme_accounts SET `+joinComma(sets)+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("update acme account %d: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) DeleteACMEAccount(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM acme_accounts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete acme account %d: %w", id, err)
	}
	return requireAffected(res)
}
