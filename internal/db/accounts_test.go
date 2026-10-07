// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestACMEAccountRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	url := "https://acme.example/acct/1"
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name:          "letsencrypt",
		DirectoryURL:  "https://acme-v02.api.letsencrypt.org/directory",
		Email:         "admin@example.com",
		AccountURL:    &url,
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
		ValidityDays:  90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("CreateACMEAccount returned id 0")
	}

	got, err := s.GetACMEAccount(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "letsencrypt" || got.Email != "admin@example.com" {
		t.Errorf("account = %+v", got)
	}
	if got.AccountURL == nil || *got.AccountURL != url {
		t.Errorf("AccountURL = %v, want %q", got.AccountURL, url)
	}
	if !strings.Contains(got.PrivateKeyPEM, "BEGIN PRIVATE KEY") {
		t.Errorf("PrivateKeyPEM = %q, want the stored PEM", got.PrivateKeyPEM)
	}
	if got.ValidityDays != 90 {
		t.Errorf("ValidityDays = %d, want 90", got.ValidityDays)
	}
	if got.CreatedAt == "" || got.UpdatedAt == "" {
		t.Error("timestamps not populated by the DB defaults")
	}
}

func TestACMEAccountPrivateKeyNeverSerialized(t *testing.T) {
	// 账户私钥等同于对 CA 的身份凭证，任何 API 响应都不能带上它。
	raw, err := json.Marshal(ACMEAccount{
		Name:          "x",
		PrivateKeyPEM: "SUPER-SECRET-KEY-MATERIAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SUPER-SECRET-KEY-MATERIAL") {
		t.Fatalf("marshalled account leaks the private key: %s", raw)
	}
	if strings.Contains(string(raw), "privateKey") {
		t.Errorf("marshalled account exposes a privateKey field: %s", raw)
	}
}

func TestGetACMEAccountMissing(t *testing.T) {
	s := NewTestDB(t)
	if _, err := s.GetACMEAccount(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetACMEAccount(999) = %v, want ErrNotFound", err)
	}
}

func TestListACMEAccountsNewestFirst(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	for _, n := range []string{"first", "second"} {
		if _, err := s.CreateACMEAccount(ctx, ACMEAccount{
			Name: n, DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
		}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListACMEAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "second" {
		t.Errorf("list[0].Name = %q, want %q (newest first)", list[0].Name, "second")
	}
}

func TestListACMEAccountsEmptyIsNotNil(t *testing.T) {
	s := NewTestDB(t)
	list, err := s.ListACMEAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Error("ListACMEAccounts returned nil, want an empty non-nil slice")
	}
}

func TestUpdateACMEAccountIsSparse(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "old", DirectoryURL: "d", Email: "old@example.com",
		PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}

	newName := "new"
	if err := s.UpdateACMEAccount(ctx, id, ACMEAccountUpdate{Name: &newName}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetACMEAccount(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "new" {
		t.Errorf("Name = %q, want new", got.Name)
	}
	if got.Email != "old@example.com" {
		t.Errorf("Email = %q, want it untouched by a name-only update", got.Email)
	}
	if got.DirectoryURL != "d" {
		t.Errorf("DirectoryURL = %q, want it immutable", got.DirectoryURL)
	}
}

func TestUpdateACMEAccountMissing(t *testing.T) {
	// UPDATE 影响 0 行在 SQLite 里不是错误，必须显式报 ErrNotFound，
	// 否则 API 会对一个不存在的 id 返回 200。
	s := NewTestDB(t)
	name := "x"
	err := s.UpdateACMEAccount(context.Background(), 999, ACMEAccountUpdate{Name: &name})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateACMEAccount(999) = %v, want ErrNotFound", err)
	}
}

func TestUpdateACMEAccountEmptyPatchStillChecksExistence(t *testing.T) {
	s := NewTestDB(t)
	if err := s.UpdateACMEAccount(context.Background(), 999, ACMEAccountUpdate{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("empty patch against a missing id = %v, want ErrNotFound", err)
	}
}

func TestDeleteACMEAccount(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "x", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteACMEAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetACMEAccount(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("account still present after delete: %v", err)
	}
	if err := s.DeleteACMEAccount(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}
