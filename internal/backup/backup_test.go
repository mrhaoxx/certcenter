// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/mrhaoxx/certcenter/internal/db"
)

var testNow = time.Unix(1_700_000_000, 0).UTC()

// seed builds a store holding the kinds of secret a real deployment has.
func seed(t *testing.T) *db.SQLite {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	if _, err := store.DB.Exec(`
		INSERT INTO acme_accounts (name, directory_url, email, private_key)
		VALUES ('le', 'https://acme.example/dir', 'a@b.c', '-----BEGIN PRIVATE KEY-----ACCOUNT-----');
		INSERT INTO dns_providers (name, kind, config)
		VALUES ('cf', 'cloudflare', '{"api_token":"super-secret"}');
		INSERT INTO certificates (domain, acme_account_id, dns_provider_id, key_pem)
		VALUES ('example.com', 1, 1, '-----BEGIN PRIVATE KEY-----LEAF-----');
	`); err != nil {
		t.Fatal(err)
	}
	return store
}

// unpack decrypts and untars an archive, returning each member's bytes.
func unpack(t *testing.T, archive []byte, passphrase string) map[string][]byte {
	t.Helper()
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := age.Decrypt(bytes.NewReader(archive), identity)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	zr, err := gzip.NewReader(decrypted)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	out := map[string][]byte{}
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("untar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = body
	}
	return out
}

func TestCreateRoundTrip(t *testing.T) {
	// The point of the whole package: an archive must restore to a database
	// that is intact and still holds the secrets. A backup nobody has
	// restored is a guess.
	store := seed(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte("[auth]\nsession_key = \"abc\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const pass = "correct horse battery staple"
	var buf bytes.Buffer
	manifest, err := Create(context.Background(), store.DB, configPath, pass, &buf, testNow)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}

	if manifest.ACMEAccounts != 1 || manifest.DNSProviders != 1 || manifest.Certificates != 1 {
		t.Errorf("manifest = %+v, want one of each", manifest)
	}
	if !manifest.HasConfig {
		t.Error("HasConfig = false, want the config included")
	}

	members := unpack(t, buf.Bytes(), pass)
	for _, want := range []string{"manifest.json", "certcenter.db", "config.toml"} {
		if _, ok := members[want]; !ok {
			t.Fatalf("archive is missing %q; has %v", want, keys(members))
		}
	}

	var restoredManifest Manifest
	if err := json.Unmarshal(members["manifest.json"], &restoredManifest); err != nil {
		t.Fatal(err)
	}
	if restoredManifest.Format != Format {
		t.Errorf("format = %q, want %q", restoredManifest.Format, Format)
	}

	// Write the database out and open it for real.
	restored := filepath.Join(dir, "restored.db")
	if err := os.WriteFile(restored, members["certcenter.db"], 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := sql.Open("sqlite", "file:"+restored)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	var integrity string
	if err := handle.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("integrity_check = %q, want ok", integrity)
	}

	// The secrets must actually be there — a structurally valid but empty
	// database would pass every check above.
	var accountKey, providerConfig, leafKey string
	if err := handle.QueryRow("SELECT private_key FROM acme_accounts").Scan(&accountKey); err != nil {
		t.Fatal(err)
	}
	if err := handle.QueryRow("SELECT config FROM dns_providers").Scan(&providerConfig); err != nil {
		t.Fatal(err)
	}
	if err := handle.QueryRow("SELECT key_pem FROM certificates").Scan(&leafKey); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(accountKey, "ACCOUNT") {
		t.Errorf("ACME account key = %q", accountKey)
	}
	if !strings.Contains(providerConfig, "super-secret") {
		t.Errorf("provider config = %q", providerConfig)
	}
	if !strings.Contains(leafKey, "LEAF") {
		t.Errorf("certificate key = %q", leafKey)
	}
}

func TestCreateRejectsWeakPassphrase(t *testing.T) {
	store := seed(t)
	var buf bytes.Buffer
	_, err := Create(context.Background(), store.DB, "", "short", &buf, testNow)
	if err == nil {
		t.Fatal("Create with a short passphrase = nil error, want rejection")
	}
	if buf.Len() != 0 {
		t.Error("Create wrote output despite rejecting the passphrase")
	}
}

func TestWrongPassphraseFailsToDecrypt(t *testing.T) {
	store := seed(t)
	var buf bytes.Buffer
	if _, err := Create(context.Background(), store.DB, "", "the right passphrase", &buf, testNow); err != nil {
		t.Fatal(err)
	}
	identity, err := age.NewScryptIdentity("the wrong passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := age.Decrypt(bytes.NewReader(buf.Bytes()), identity); err == nil {
		t.Error("decrypting with the wrong passphrase succeeded")
	}
}

func TestCreateWithoutConfig(t *testing.T) {
	// A missing config must not fail the backup: the database is the part
	// that cannot be reconstructed.
	store := seed(t)
	var buf bytes.Buffer
	m, err := Create(context.Background(), store.DB, "/nonexistent/config.toml", "a passphrase long enough", &buf, testNow)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if m.HasConfig {
		t.Error("HasConfig = true with no config file")
	}
	members := unpack(t, buf.Bytes(), "a passphrase long enough")
	if _, ok := members["config.toml"]; ok {
		t.Error("archive contains config.toml that does not exist")
	}
	if _, ok := members["certcenter.db"]; !ok {
		t.Error("archive is missing the database")
	}
}

func TestFilenameIsSortable(t *testing.T) {
	got := Filename(testNow)
	if !strings.HasPrefix(got, "certcenter-2023") || !strings.HasSuffix(got, ".tar.gz.age") {
		t.Errorf("Filename() = %q", got)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
