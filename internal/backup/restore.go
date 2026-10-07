// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

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
	"sort"
	"strings"

	"filippo.io/age"
)

// Restorable lists the tables a restore replaces, in an order that keeps
// foreign keys satisfied while inserting.
//
// settings is included because it holds the admin password: a restore that
// silently kept the current one would not be a restore. The operator is
// told, since it means logging in with the password from the backup's era.
var Restorable = []string{
	"acme_accounts",
	"dns_providers",
	"deploy_targets",
	"certificates",
	"deployments",
	"runs",
	"events",
	"operation_logs",
	"settings",
}

// RestoreReport says what was put back, for the operator to check against
// what they expected.
type RestoreReport struct {
	Manifest Manifest       `json:"manifest"`
	Rows     map[string]int `json:"rows"`
	// SkippedColumns names columns the archive carried that this schema no
	// longer has, or vice versa. Empty is the normal case.
	SkippedColumns []string `json:"skippedColumns"`
}

// Restore replaces the live data with an archive's contents.
//
// The database is not swapped on disk. The process holds it open, in WAL
// mode, and replacing the file underneath would at best need a restart and
// at worst corrupt it. Instead the archive is attached and the rows are
// moved across inside one transaction: either the whole restore lands or
// none of it does, and the service keeps running throughout.
func Restore(ctx context.Context, db *sql.DB, archive io.Reader, passphrase string) (RestoreReport, error) {
	var report RestoreReport

	work, err := os.MkdirTemp("", "certcenter-restore-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)

	dbPath, manifest, err := extractArchive(work, archive, passphrase)
	if err != nil {
		return report, err
	}
	report.Manifest = manifest

	// Check the archive before touching anything live: a truncated or
	// corrupt database must not take the running one down with it.
	if err := verifyArchiveDB(ctx, dbPath); err != nil {
		return report, err
	}

	rows, skipped, err := copyIn(ctx, db, dbPath)
	if err != nil {
		return report, err
	}
	report.Rows = rows
	report.SkippedColumns = skipped
	return report, nil
}

// unpack decrypts and extracts, returning the database's path.
func extractArchive(work string, archive io.Reader, passphrase string) (string, Manifest, error) {
	var manifest Manifest
	if passphrase == "" {
		return "", manifest, fmt.Errorf("the passphrase is required to open the archive")
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return "", manifest, err
	}
	decrypted, err := age.Decrypt(archive, identity)
	if err != nil {
		// Nearly always the wrong passphrase, and saying so beats relaying
		// a cryptographic error.
		return "", manifest, fmt.Errorf("could not open the archive; check the passphrase: %w", err)
	}
	zr, err := gzip.NewReader(decrypted)
	if err != nil {
		return "", manifest, fmt.Errorf("the archive is not gzipped as expected: %w", err)
	}

	dbPath := ""
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", manifest, fmt.Errorf("read the archive: %w", err)
		}
		// Only the names this package writes are extracted; a crafted
		// archive must not be able to write outside the temporary
		// directory.
		switch filepath.Base(hdr.Name) {
		case "certcenter.db":
			dbPath = filepath.Join(work, "certcenter.db")
			out, err := os.Create(dbPath)
			if err != nil {
				return "", manifest, err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, 1<<30)); err != nil {
				out.Close()
				return "", manifest, err
			}
			out.Close()
		case "manifest.json":
			body, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return "", manifest, err
			}
			_ = json.Unmarshal(body, &manifest)
		}
	}
	if dbPath == "" {
		return "", manifest, fmt.Errorf("the archive holds no certcenter.db")
	}
	if manifest.Format != "" && manifest.Format != Format {
		return "", manifest, fmt.Errorf("the archive is format %q, and this reads %q",
			manifest.Format, Format)
	}
	return dbPath, manifest, nil
}

// verifyArchiveDB refuses an archive that is not a sound database holding
// what we expect.
func verifyArchiveDB(ctx context.Context, path string) error {
	handle, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open the archive's database: %w", err)
	}
	defer handle.Close()

	var integrity string
	if err := handle.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("the archive's database is unreadable: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("the archive's database fails integrity_check: %s", integrity)
	}
	var n int
	if err := handle.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='certificates'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("the archive's database has no certificates table; it is not a CertCenter backup")
	}
	return nil
}

// copyIn replaces the live tables from the attached archive.
func copyIn(ctx context.Context, db *sql.DB, archivePath string) (map[string]int, []string, error) {
	// ATTACH has to happen outside the transaction; SQLite refuses it
	// inside one.
	if _, err := db.ExecContext(ctx, `ATTACH DATABASE ? AS backup`, "file:"+archivePath+"?mode=ro"); err != nil {
		return nil, nil, fmt.Errorf("attach the archive: %w", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DETACH DATABASE backup`) }()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	// Foreign keys are deferred for the duration: the tables are emptied
	// before any is refilled, so mid-restore the references are dangling by
	// construction.
	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return nil, nil, err
	}

	rows := map[string]int{}
	skippedSet := map[string]bool{}

	for i := len(Restorable) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, `DELETE FROM main.`+Restorable[i]); err != nil {
			return nil, nil, fmt.Errorf("clear %s: %w", Restorable[i], err)
		}
	}

	for _, table := range Restorable {
		live, err := columnsOf(ctx, tx, "main", table)
		if err != nil {
			return nil, nil, err
		}
		archived, err := columnsOf(ctx, tx, "backup", table)
		if err != nil {
			// A table the archive predates simply has nothing to restore.
			continue
		}

		// Copy the columns both sides know. An older archive lacks columns
		// added since, and a newer one carries columns this build has not
		// heard of; either way the shared set is what can be moved, and
		// "INSERT ... SELECT *" would fail outright on the count mismatch.
		var shared []string
		for c := range archived {
			if live[c] {
				shared = append(shared, c)
			} else {
				skippedSet[table+"."+c] = true
			}
		}
		for c := range live {
			if !archived[c] {
				skippedSet[table+"."+c] = true
			}
		}
		// Deterministic order keeps the generated SQL stable.
		sort.Strings(shared)
		if len(shared) == 0 {
			continue
		}

		list := strings.Join(shared, ", ")
		res, err := tx.ExecContext(ctx, fmt.Sprintf(
			`INSERT INTO main.%s (%s) SELECT %s FROM backup.%s`, table, list, list, table))
		if err != nil {
			return nil, nil, fmt.Errorf("restore %s: %w", table, err)
		}
		n, _ := res.RowsAffected()
		rows[table] = int(n)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit the restore: %w", err)
	}

	skipped := make([]string, 0, len(skippedSet))
	for c := range skippedSet {
		skipped = append(skipped, c)
	}
	return rows, skipped, nil
}

func columnsOf(ctx context.Context, tx *sql.Tx, schema, table string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("PRAGMA %s.table_info(%s)", schema, table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notNull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s.%s has no columns", schema, table)
	}
	return out, rows.Err()
}
