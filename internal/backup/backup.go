// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package backup produces an encrypted snapshot of everything CertCenter
// cannot regenerate.
//
// One SQLite file holds every secret the service has: ACME account private
// keys, DNS and deploy-target credentials, certificate private keys, and
// the admin password hash. Losing it means re-registering with each CA and
// re-entering every credential by hand.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// MinPassphraseLength guards the archive. The plaintext is a pile of
// private keys, so a passphrase short enough to brute-force defeats the
// whole exercise.
const MinPassphraseLength = 12

// Format identifies the archive layout, so a future reader can tell what
// it is holding before unpacking it.
const Format = "certcenter-backup-v1"

// Manifest travels inside the archive and is also returned to the caller
// for logging and for the UI to display.
type Manifest struct {
	Format    string `json:"format"`
	CreatedAt string `json:"createdAt"`
	// Counts let someone confirm at a glance that a restore landed the
	// data they expected, without decrypting and querying by hand.
	ACMEAccounts int  `json:"acmeAccounts"`
	DNSProviders int  `json:"dnsProviders"`
	DeployTarget int  `json:"deployTargets"`
	Certificates int  `json:"certificates"`
	HasConfig    bool `json:"hasConfig"`
}

// Create writes an age-encrypted, gzipped tar of the database and config
// to w.
//
// The snapshot comes from VACUUM INTO rather than a file copy: the
// database runs in WAL mode, where copying the file mid-write yields a
// torn image that only announces itself at restore time. VACUUM INTO goes
// through SQLite's own machinery and emits a consistent, compacted
// database.
//
// The archive is a standard age file, readable by the age command line —
// a backup that only its own tool can open is a liability.
func Create(ctx context.Context, db *sql.DB, configPath, passphrase string, w io.Writer, now time.Time) (Manifest, error) {
	var m Manifest
	if len(passphrase) < MinPassphraseLength {
		return m, fmt.Errorf("the passphrase must be at least %d characters", MinPassphraseLength)
	}

	work, err := os.MkdirTemp("", "certcenter-backup-")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(work)

	// VACUUM INTO refuses to overwrite, so the path must not exist yet.
	snapshot := filepath.Join(work, "certcenter.db")
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", snapshot); err != nil {
		return m, fmt.Errorf("snapshot the database: %w", err)
	}

	m = Manifest{Format: Format, CreatedAt: now.UTC().Format(time.RFC3339)}
	if err := countInto(ctx, db, &m); err != nil {
		return m, err
	}

	files := map[string]string{"certcenter.db": snapshot}
	if configPath != "" {
		if raw, err := os.ReadFile(configPath); err == nil {
			p := filepath.Join(work, "config.toml")
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				return m, err
			}
			files["config.toml"] = p
			m.HasConfig = true
		}
		// A missing or unreadable config is not fatal: the database is what
		// cannot be reconstructed, and config.toml can be rewritten by hand.
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return m, fmt.Errorf("prepare encryption: %w", err)
	}
	encrypted, err := age.Encrypt(w, recipient)
	if err != nil {
		return m, fmt.Errorf("start encryption: %w", err)
	}
	zw := gzip.NewWriter(encrypted)
	tw := tar.NewWriter(zw)

	manifestJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := writeTarBytes(tw, "manifest.json", manifestJSON, now); err != nil {
		return m, err
	}
	for name, path := range files {
		if err := writeTarFile(tw, name, path, now); err != nil {
			return m, err
		}
	}

	// Close in order: tar, gzip, then the age writer. Skipping any of these
	// truncates the archive, and age in particular writes its
	// authentication tag on Close — an unclosed file fails to decrypt.
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := zw.Close(); err != nil {
		return m, err
	}
	if err := encrypted.Close(); err != nil {
		return m, err
	}
	return m, nil
}

func countInto(ctx context.Context, db *sql.DB, m *Manifest) error {
	for _, c := range []struct {
		table string
		dst   *int
	}{
		{"acme_accounts", &m.ACMEAccounts},
		{"dns_providers", &m.DNSProviders},
		{"deploy_targets", &m.DeployTarget},
		{"certificates", &m.Certificates},
	} {
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM "+c.table).Scan(c.dst); err != nil {
			return fmt.Errorf("count %s: %w", c.table, err)
		}
	}
	return nil
}

func writeTarBytes(tw *tar.Writer, name string, body []byte, now time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: int64(len(body)), ModTime: now,
	}); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func writeTarFile(tw *tar.Writer, name, path string, now time.Time) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o600, Size: info.Size(), ModTime: now,
	}); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

// Filename is the suggested download name.
func Filename(now time.Time) string {
	return "certcenter-" + now.UTC().Format("20060102T150405Z") + ".tar.gz.age"
}
