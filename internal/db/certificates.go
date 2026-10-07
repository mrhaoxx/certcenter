// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const certificateColumns = `id, domain, sans, acme_account_id, dns_provider_id,
	cert_pem, chain_pem, key_pem, serial, not_before, not_after, renew_after,
	validity_days, profile, status, last_error, auto_renew, skip_dns_check, skip_dns_wait_seconds, rotate_key, key_type, preferred_chain,
	not_before_days, extended_key_usage, renew_before_days, revoked_at, revocation_reason, csr_pem, retry_count, retry_after,
	created_at, updated_at`

// rfc3339 is how the application formats every timestamp it writes.
// julianday() parses this as well as SQLite's own datetime() layout, which
// is what the renewal query needs.
const rfc3339 = time.RFC3339

func scanCertificate(row interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var sansJSON string
	var keyPEM sql.NullString
	err := row.Scan(&c.ID, &c.Domain, &sansJSON, &c.ACMEAccountID, &c.DNSProviderID,
		&c.CertPEM, &c.ChainPEM, &keyPEM, &c.Serial, &c.NotBefore, &c.NotAfter,
		&c.RenewAfter, &c.ValidityDays, &c.Profile, &c.Status, &c.LastError, &c.AutoRenew, &c.SkipDNSCheck, &c.SkipDNSWaitSeconds, &c.RotateKey, &c.KeyType, &c.PreferredChain,
		&c.NotBeforeDays, &c.ExtendedKeyUsage, &c.RenewBeforeDays, &c.RevokedAt, &c.RevocationReason, &c.CSRPEM,
		&c.RetryCount, &c.RetryAfter, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.KeyPEM = keyPEM.String
	c.SANs = []string{}
	if sansJSON != "" {
		if err := json.Unmarshal([]byte(sansJSON), &c.SANs); err != nil {
			return nil, fmt.Errorf("certificate %d has malformed sans: %w", c.ID, err)
		}
		if c.SANs == nil {
			c.SANs = []string{}
		}
	}
	return &c, nil
}

func (s *SQLite) CreateCertificate(ctx context.Context, c Certificate) (int64, error) {
	// ValidityDays is left at zero on purpose. It now becomes the order's
	// notAfter, and zero means "request no particular lifetime" — the only
	// safe default, since Let's Encrypt rejects any order carrying one.
	if c.ValidityDays < 0 {
		c.ValidityDays = 0
	}
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	encoded, err := json.Marshal(sans)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO certificates (domain, sans, acme_account_id, dns_provider_id,
			validity_days, profile, auto_renew, skip_dns_check, skip_dns_wait_seconds, rotate_key, key_type,
			preferred_chain, not_before_days, extended_key_usage, renew_before_days, csr_pem)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Domain, string(encoded), c.ACMEAccountID, c.DNSProviderID,
		c.ValidityDays, c.Profile, c.AutoRenew, c.SkipDNSCheck, c.SkipDNSWaitSeconds, c.RotateKey, c.KeyType,
		c.PreferredChain, c.NotBeforeDays, c.ExtendedKeyUsage, c.RenewBeforeDays, c.CSRPEM)
	if err != nil {
		return 0, fmt.Errorf("create certificate: %w", err)
	}
	return res.LastInsertId()
}

func (s *SQLite) GetCertificate(ctx context.Context, id int64) (*Certificate, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT `+certificateColumns+` FROM certificates WHERE id = ?`, id)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get certificate %d: %w", id, err)
	}
	return c, nil
}

func (s *SQLite) ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, error) {
	query := `SELECT ` + certificateColumns + ` FROM certificates WHERE 1=1`
	args := []any{}
	if f.Search != "" {
		query += ` AND (domain LIKE ? OR sans LIKE ?)`
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY id DESC`

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
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

func (s *SQLite) UpdateCertificateStatus(ctx context.Context, id int64, status, lastErr string) error {
	var errValue any
	if lastErr != "" {
		errValue = lastErr
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET status = ?, last_error = ?, updated_at = datetime('now')
		 WHERE id = ?`, status, errValue, id)
	if err != nil {
		return fmt.Errorf("update certificate %d status: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) SaveIssuedCertificate(ctx context.Context, id int64, issued IssuedCertificate) error {
	var renewAfter any
	if issued.RenewAfter != nil {
		renewAfter = issued.RenewAfter.UTC().Format(rfc3339)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET
			cert_pem = ?, chain_pem = ?, key_pem = ?, serial = ?,
			not_before = ?, not_after = ?, renew_after = ?,
			status = 'issued', last_error = NULL,
			retry_count = 0, retry_after = NULL,
			updated_at = datetime('now')
		 WHERE id = ?`,
		issued.CertPEM, issued.ChainPEM, issued.KeyPEM, issued.Serial,
		issued.NotBefore.UTC().Format(rfc3339), issued.NotAfter.UTC().Format(rfc3339),
		renewAfter, id)
	if err != nil {
		return fmt.Errorf("save issued certificate %d: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) DeleteCertificate(ctx context.Context, id int64) error {
	// runs/events/deployments cascade via the schema's foreign keys, which
	// are enabled by the DSN.
	res, err := s.DB.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete certificate %d: %w", id, err)
	}
	return requireAffected(res)
}

// UpdateCertificateSettings applies the operator-editable fields. Nil
// leaves a field unchanged.
// UpdateCertificateSettings applies a sparse update.
//
// The fields arrive in a struct rather than as parameters: this began with
// three and reached eight, at which point the call site said nothing about
// which argument was which.
func (s *SQLite) UpdateCertificateSettings(ctx context.Context, id int64, u CertificateSettings) error {
	sets := []string{}
	args := []any{}
	addBool := func(col string, v *bool) {
		if v != nil {
			sets = append(sets, col+" = ?")
			args = append(args, *v)
		}
	}
	addInt := func(col string, v *int64) {
		if v != nil {
			sets = append(sets, col+" = ?")
			args = append(args, *v)
		}
	}
	addStr := func(col string, v *string) {
		if v != nil {
			sets = append(sets, col+" = ?")
			args = append(args, *v)
		}
	}

	addInt("acme_account_id", u.ACMEAccountID)
	addBool("auto_renew", u.AutoRenew)
	addInt("validity_days", u.ValidityDays)
	addStr("profile", u.Profile)
	addBool("skip_dns_check", u.SkipDNSCheck)
	addBool("rotate_key", u.RotateKey)
	addStr("key_type", u.KeyType)
	addStr("preferred_chain", u.PreferredChain)
	addInt("not_before_days", u.NotBeforeDays)
	addStr("extended_key_usage", u.ExtendedKeyUsage)
	addInt("renew_before_days", u.RenewBeforeDays)
	// Double pointer: the outer says "the caller mentioned this field", the
	// inner carries nil for "inherit the global wait".
	if u.SkipDNSWaitSeconds != nil {
		sets = append(sets, "skip_dns_wait_seconds = ?")
		args = append(args, *u.SkipDNSWaitSeconds)
	}

	if len(sets) == 0 {
		if _, err := s.GetCertificate(ctx, id); err != nil {
			return err
		}
		return nil
	}
	sets = append(sets, "updated_at = datetime('now')")
	args = append(args, id)

	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET `+joinComma(sets)+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("update certificate %d settings: %w", id, err)
	}
	return requireAffected(res)
}

// MarkRevoked records that the CA revoked this certificate.
//
// The material stays in the row on purpose: an operator investigating why
// a service broke needs to see what was revoked and when, and deleting it
// would leave the timeline pointing at nothing.
func (s *SQLite) MarkRevoked(ctx context.Context, id int64, reason string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates
		 SET status = 'revoked', auto_renew = 0, revoked_at = datetime('now'),
		     revocation_reason = ?, updated_at = datetime('now')
		 WHERE id = ?`, reason, id)
	if err != nil {
		return fmt.Errorf("mark revoked: %w", err)
	}
	return requireAffected(res)
}
