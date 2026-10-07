// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// makeCSR builds a request for the given names with a throwaway key,
// standing in for one produced by an HSM.
func makeCSR(t *testing.T, names ...string) string {
	t.Helper()
	signer, _, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := BuildCSR(signer, names, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssueFromSuppliedCSR(t *testing.T) {
	// The point: the private key never reaches this service, so nothing is
	// stored for it and the certificate still issues.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "csr.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(`UPDATE certificates SET csr_pem = ? WHERE id = ?`,
		makeCSR(t, "csr.example.com"), certID); err != nil {
		t.Fatal(err)
	}

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() from a supplied CSR = %v", err)
	}
	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "issued" {
		t.Fatalf("status = %q, want issued", c.Status)
	}
	if c.KeyPEM != "" {
		t.Error("a private key was stored; the whole point is that we never hold one")
	}
	if c.CertPEM == nil || *c.CertPEM == "" {
		t.Error("no certificate was stored")
	}

	// The issued certificate must carry the CSR's public key.
	block, _ := pem.Decode([]byte(*c.CertPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "csr.example.com" {
		t.Errorf("certificate SANs = %v", leaf.DNSNames)
	}
}

func TestParseCSRRejectsMismatchedNames(t *testing.T) {
	// A CSR covering something else would either be refused by the CA or
	// return a certificate for names nobody ordered.
	tests := []struct {
		name          string
		csrNames      []string
		orderedNames  []string
		wantSubstring string
	}{
		{"CSR 少了订单里的名字", []string{"a.example.com"},
			[]string{"a.example.com", "b.example.com"}, "does not cover"},
		{"CSR 多了订单外的名字", []string{"a.example.com", "evil.example.com"},
			[]string{"a.example.com"}, "does not order"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCSR(makeCSR(t, tt.csrNames...), tt.orderedNames)
			if err == nil {
				t.Fatal("ParseCSR accepted a mismatched CSR")
			}
			if !strings.Contains(err.Error(), tt.wantSubstring) {
				t.Errorf("error = %v, want it to mention %q", err, tt.wantSubstring)
			}
		})
	}
}

func TestParseCSRRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"not pem",
		"-----BEGIN CERTIFICATE REQUEST-----\nbm90IGRlcg==\n-----END CERTIFICATE REQUEST-----\n",
	} {
		if _, err := ParseCSR(in, []string{"a.example.com"}); err == nil {
			t.Errorf("ParseCSR(%.20q) = nil error, want failure", in)
		}
	}
}

func TestParseCSRAcceptsAnExactMatch(t *testing.T) {
	der, err := ParseCSR(makeCSR(t, "a.example.com", "b.example.com"),
		[]string{"b.example.com", "a.example.com"}) // order must not matter
	if err != nil {
		t.Fatalf("ParseCSR = %v", err)
	}
	if len(der) == 0 {
		t.Error("ParseCSR returned no DER")
	}
}
