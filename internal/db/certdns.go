// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
)

// ListCertificateDNSProviders returns the providers a certificate may use,
// ordered by id so a pipeline's behaviour does not depend on map ordering.
func (s *SQLite) ListCertificateDNSProviders(ctx context.Context, certID int64) ([]DNSProvider, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT p.id, p.name, p.kind, p.config, p.created_at, p.updated_at
		   FROM dns_providers p
		   JOIN certificate_dns_providers c ON c.dns_provider_id = p.id
		  WHERE c.certificate_id = ?
		  ORDER BY p.id`, certID)
	if err != nil {
		return nil, fmt.Errorf("list the certificate's DNS providers: %w", err)
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

// SetCertificateDNSProviders replaces the set. An empty list is refused:
// a certificate with no provider can never be issued, and failing here
// beats failing at the first challenge.
func (s *SQLite) SetCertificateDNSProviders(ctx context.Context, certID int64, providerIDs []int64) error {
	if len(providerIDs) == 0 {
		return fmt.Errorf("a certificate needs at least one DNS provider")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM certificate_dns_providers WHERE certificate_id = ?`, certID); err != nil {
		return err
	}
	for _, id := range providerIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO certificate_dns_providers (certificate_id, dns_provider_id)
			 VALUES (?, ?)`, certID, id); err != nil {
			return fmt.Errorf("attach DNS provider %d: %w", id, err)
		}
	}
	// dns_provider_id is NOT NULL and still written so an older reader —
	// and the column's own constraint — stay satisfied.
	if _, err := tx.ExecContext(ctx,
		`UPDATE certificates SET dns_provider_id = ?, updated_at = datetime('now') WHERE id = ?`,
		providerIDs[0], certID); err != nil {
		return err
	}
	return tx.Commit()
}
