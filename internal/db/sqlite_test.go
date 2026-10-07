// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestSchemaCreatesEveryTable(t *testing.T) {
	s := NewTestDB(t)

	rows, err := s.DB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)

	want := []string{
		"acme_accounts", "certificate_dns_providers", "certificates", "deploy_targets", "deployments",
		"dns_providers", "events", "operation_logs", "runs", "settings",
	}
	if len(got) != len(want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tables = %v, want %v", got, want)
			break
		}
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	// 现有 Rust 实现声明了外键却从未启用 PRAGMA，级联全靠手写 SQL。
	// 这个测试锁住"外键真的开着"。
	s := NewTestDB(t)

	var on int
	if err := s.DB.QueryRow("PRAGMA foreign_keys").Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1", on)
	}

	// 指向不存在的账户必须被拒绝。
	_, err := s.DB.Exec(`INSERT INTO certificates (domain, acme_account_id, dns_provider_id)
	                     VALUES ('x.example.com', 999, 999)`)
	if err == nil {
		t.Fatal("insert with dangling FK succeeded, want a constraint error")
	}
}

func TestDeletingCertificateCascades(t *testing.T) {
	s := NewTestDB(t)
	certID := seedCertificate(t, s)

	if _, err := s.DB.Exec(`INSERT INTO runs (kind, certificate_id, attempt, trigger)
	                        VALUES ('issue', ?, 1, 'manual')`, certID); err != nil {
		t.Fatal(err)
	}
	var runID int64
	if err := s.DB.QueryRow("SELECT id FROM runs WHERE certificate_id = ?", certID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO events (run_id, seq, type, message)
	                        VALUES (?, 1, 'start', 'hello')`, runID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.Exec("DELETE FROM certificates WHERE id = ?", certID); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"runs", "events"} {
		var n int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows after deleting the certificate, want 0", table, n)
		}
	}
}

func TestOpenFileDBUsesWAL(t *testing.T) {
	// 内存库的 journal_mode 返回 "memory"，所以 WAL 只能在文件库上断言。
	path := filepath.Join(t.TempDir(), "cc.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer s.Close()

	var mode string
	if err := s.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	// schema 用 CREATE TABLE IF NOT EXISTS，重开已有库不能报错。
	path := filepath.Join(t.TempDir(), "cc.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing database failed: %v", err)
	}
	second.Close()
}

// NewTestDB 返回跑真实 schema 的内存库，测试结束时关闭。
func NewTestDB(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenMemory()
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedCertificate 插入一条证书及其依赖的账户与 DNS 提供商，返回证书 id。
func seedCertificate(t *testing.T, s *SQLite) int64 {
	t.Helper()
	res, err := s.DB.Exec(`INSERT INTO acme_accounts (name, directory_url, email, private_key)
	                       VALUES ('le', 'https://acme.example/dir', 'a@b.c', 'PEM')`)
	if err != nil {
		t.Fatal(err)
	}
	acctID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.DB.Exec(`INSERT INTO dns_providers (name, kind, config)
	                      VALUES ('cf', 'cloudflare', '{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.DB.Exec(`INSERT INTO certificates (domain, acme_account_id, dns_provider_id)
	                      VALUES ('x.example.com', ?, ?)`, acctID, dnsID)
	if err != nil {
		t.Fatal(err)
	}
	certID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return certID
}
