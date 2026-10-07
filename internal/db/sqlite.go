// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package db is CertCenter's persistence layer: SQLite via a pure-Go
// driver so the binary builds with CGO_ENABLED=0.
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var Schema string

// SQLite is the Store implementation.
type SQLite struct {
	DB *sql.DB
}

// Open opens (creating if absent) the database at path, applies the
// pragmas, and runs the schema.
func Open(path string) (*SQLite, error) {
	return open(dsn(path))
}

// OpenMemory opens a private in-memory database with the real schema. It
// exists for tests — including tests in other packages, which is why it
// lives here rather than in a _test.go file. It deliberately takes no
// *testing.T: importing "testing" from a non-test file would link the test
// framework (and its -test.* flags) into the production binary.
//
// journal_mode is left alone: WAL does not apply to an in-memory database,
// which reports "memory" instead.
func OpenMemory() (*SQLite, error) {
	return open("file::memory:?_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)")
}

// dsn builds a modernc.org/sqlite DSN. foreign_keys is ON because the
// schema relies on ON DELETE CASCADE; WAL plus a busy timeout keeps the
// scheduler's writes from colliding with a request.
func dsn(path string) string {
	return "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(on)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)"
}

func open(dsn string) (*SQLite, error) {
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite has a single writer. Writes here are rare (issuance, deploys,
	// events), so one connection trades negligible throughput for the
	// whole class of SQLITE_BUSY races.
	handle.SetMaxOpenConns(1)

	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := handle.Exec(Schema); err != nil {
		handle.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(handle); err != nil {
		handle.Close()
		return nil, err
	}
	return &SQLite{DB: handle}, nil
}

// addedColumn is a column introduced after the initial schema. schema.sql
// uses CREATE TABLE IF NOT EXISTS, which does nothing to a table that
// already exists, so new columns need an explicit ALTER on databases that
// predate them.
type addedColumn struct {
	table, column, definition string
}

var addedColumns = []addedColumn{
	// The ACME profile requested for this certificate ("shortlived",
	// "tlsserver", …). Empty means "whatever the CA defaults to".
	{"certificates", "profile", "TEXT NOT NULL DEFAULT ''"},
	// Skips the DNS propagation check for this certificate only. Some zones
	// are invisible to a public resolver — split-horizon views, internal
	// DNS — yet perfectly visible to the CA, and the check would block
	// issuance for no reason.
	{"certificates", "skip_dns_check", "INTEGER NOT NULL DEFAULT 0"},
	// How long to wait when the check is skipped for this certificate.
	// NULL inherits the global setting; 0 is a deliberate "do not wait".
	{"certificates", "skip_dns_wait_seconds", "INTEGER"},
	// Renewal reuses the existing private key by default. Rotation is the
	// mainstream default (certbot rotates unless told otherwise) and limits
	// how long a leaked key stays useful, but it breaks anything pinning
	// the public key — a TLSA record with an SPKI selector has to be
	// republished on every renewal.
	{"certificates", "rotate_key", "INTEGER NOT NULL DEFAULT 0"},
	// Key algorithm for the certificate itself: "" keeps the ec-256 that
	// was hard-coded before this became a choice.
	{"certificates", "key_type", "TEXT NOT NULL DEFAULT ''"},
	// Prefer a chain whose issuer Common Name matches. A CA can offer
	// several; we took the first and discarded the rest.
	{"certificates", "preferred_chain", "TEXT NOT NULL DEFAULT ''"},
	// Requested notBefore, in the same "days from now" shape as
	// validity_days. Zero asks for nothing.
	{"certificates", "not_before_days", "INTEGER NOT NULL DEFAULT 0"},
	// Extended key usage for the CSR. Public CAs largely ignore it.
	{"certificates", "extended_key_usage", "TEXT NOT NULL DEFAULT ''"},
	// Renew this certificate once fewer than N days remain, overriding
	// both ARI and the lifetime-fraction fallback. Zero keeps them.
	{"certificates", "renew_before_days", "INTEGER NOT NULL DEFAULT 0"},
	// Revocation is recorded rather than deleting the row: someone working
	// out why a service broke needs to see what was revoked and when.
	{"certificates", "revoked_at", "TEXT"},
	{"certificates", "revocation_reason", "TEXT NOT NULL DEFAULT ''"},
	// A caller-supplied CSR. When set, issuance signs this instead of
	// generating a key, and key_pem stays empty — the private half never
	// reaches us, which is the point for a key living in an HSM.
	{"certificates", "csr_pem", "TEXT NOT NULL DEFAULT ''"},
}

// dataMigration is a one-off statement recorded in settings once applied,
// for changes that rewrite rows rather than add columns.
type dataMigration struct {
	key, stmt string
}

var dataMigrations = []dataMigration{
	// validity_days used to default to 90 and was never sent anywhere: a CA
	// issues whatever lifetime it likes unless asked through a mechanism it
	// supports. It now means "request this lifetime via the order's notAfter
	// field", and 0 means "don't ask". Existing rows carry the old
	// meaningless default, and leaving them non-zero would start sending
	// notAfter to Let's Encrypt, which rejects any order carrying it.
	{"migration_validity_days_optin", "UPDATE certificates SET validity_days = 0"},
	// Seed the many-to-many table from the single column it replaces, so a
	// certificate created before this keeps working untouched.
	{"migration_dns_providers_many", `INSERT OR IGNORE INTO certificate_dns_providers
		(certificate_id, dns_provider_id)
		SELECT id, dns_provider_id FROM certificates`},
}

// migrate applies the additive column changes, skipping any that are
// already present. Running it twice is a no-op.
func migrate(handle *sql.DB) error {
	for _, c := range addedColumns {
		present, err := columnExists(handle, c.table, c.column)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", c.table, c.column, c.definition)
		if _, err := handle.Exec(stmt); err != nil {
			return fmt.Errorf("add column %s.%s: %w", c.table, c.column, err)
		}
	}

	for _, m := range dataMigrations {
		var applied string
		err := handle.QueryRow("SELECT value FROM settings WHERE key = ?", m.key).Scan(&applied)
		if err == nil {
			continue // already applied
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("check migration %s: %w", m.key, err)
		}
		if _, err := handle.Exec(m.stmt); err != nil {
			return fmt.Errorf("apply migration %s: %w", m.key, err)
		}
		if _, err := handle.Exec(
			"INSERT INTO settings (key, value) VALUES (?, datetime('now'))", m.key); err != nil {
			return fmt.Errorf("record migration %s: %w", m.key, err)
		}
	}
	return nil
}

func columnExists(handle *sql.DB, table, column string) (bool, error) {
	rows, err := handle.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("inspect %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			ctype      string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &defaultVal, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *SQLite) Close() error { return s.DB.Close() }

// 编译期断言：SQLite 满足 Store。
var _ Store = (*SQLite)(nil)

// requireAffected turns "UPDATE/DELETE matched no rows" into ErrNotFound.
// SQLite reports success for a statement that changed nothing, so without
// this an API call against a nonexistent id would answer 200.
func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// joinComma joins SQL assignment fragments for a sparse UPDATE.
func joinComma(parts []string) string {
	return strings.Join(parts, ", ")
}

func (s *SQLite) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return v, nil
}

func (s *SQLite) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

func (s *SQLite) AppendLog(ctx context.Context, l OperationLog) error {
	operator := l.Operator
	if operator == "" {
		operator = "admin"
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO operation_logs (action, resource_type, resource_id, detail, operator)
		 VALUES (?, ?, ?, ?, ?)`,
		l.Action, l.ResourceType, l.ResourceID, l.Detail, operator)
	if err != nil {
		return fmt.Errorf("append log: %w", err)
	}
	return nil
}

func (s *SQLite) ListLogs(ctx context.Context, limit, offset int) ([]OperationLog, error) {
	if limit <= 0 {
		limit = DefaultLogLimit
	}
	if limit > MaxLogLimit {
		limit = MaxLogLimit
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, action, resource_type, resource_id, detail, operator, created_at
		 FROM operation_logs ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list logs: %w", err)
	}
	defer rows.Close()

	// Non-nil so an empty result marshals to [] rather than null.
	logs := []OperationLog{}
	for rows.Next() {
		var l OperationLog
		if err := rows.Scan(&l.ID, &l.Action, &l.ResourceType, &l.ResourceID,
			&l.Detail, &l.Operator, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
