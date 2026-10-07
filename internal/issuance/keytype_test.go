// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestGenerateCertKeyCoversEveryAdvertisedType(t *testing.T) {
	// KeyTypes() drives the API's validation and the UI's picker, so every
	// name it offers has to actually generate.
	for _, kt := range KeyTypes() {
		t.Run(kt, func(t *testing.T) {
			signer, keyPEM, err := GenerateCertKey(kt)
			if err != nil {
				t.Fatalf("GenerateCertKey(%q) = %v", kt, err)
			}
			if !strings.HasPrefix(keyPEM, "-----BEGIN PRIVATE KEY-----") {
				t.Errorf("key is not PKCS#8 PEM: %.40s", keyPEM)
			}
			// It must round-trip: renewal reuses the stored key by default.
			if _, err := ParseCertKey(keyPEM); err != nil {
				t.Errorf("the generated key does not parse back: %v", err)
			}

			switch {
			case strings.HasPrefix(kt, "ec-"):
				k, ok := signer.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("%q produced %T, want ECDSA", kt, signer)
				}
				want := map[string]string{"ec-256": "P-256", "ec-384": "P-384", "ec-521": "P-521"}[kt]
				if got := k.Curve.Params().Name; got != want {
					t.Errorf("curve = %q, want %q", got, want)
				}
			case strings.HasPrefix(kt, "rsa-"):
				k, ok := signer.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("%q produced %T, want RSA", kt, signer)
				}
				want := map[string]int{"rsa-2048": 2048, "rsa-3072": 3072, "rsa-4096": 4096}[kt]
				if got := k.N.BitLen(); got != want {
					t.Errorf("modulus = %d bits, want %d", got, want)
				}
			}
		})
	}
}

func TestGenerateCertKeyDefaultsAndRejects(t *testing.T) {
	signer, _, err := GenerateCertKey("")
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := signer.(*ecdsa.PrivateKey); !ok || k.Curve.Params().Name != "P-256" {
		t.Errorf("the empty key type did not fall back to %s", DefaultKeyType)
	}
	if _, _, err := GenerateCertKey("rsa-1024"); err == nil {
		t.Error("GenerateCertKey accepted an unsupported type")
	}
}

func TestIssueWithRSAKey(t *testing.T) {
	// The point of the option: a target that only accepts RSA could not be
	// served at all while ec-256 was hard-coded.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "rsa.example.com", nil)
	store := is.Store.(*db.SQLite)
	if _, err := store.DB.Exec(
		`UPDATE certificates SET key_type = 'rsa-2048' WHERE id = ?`, certID); err != nil {
		t.Fatal(err)
	}

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}
	c, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ParseCertKey(c.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := signer.(*rsa.PrivateKey); !ok {
		t.Fatalf("stored key is %T, want RSA", signer)
	}
	// And the issued certificate must carry the RSA public key, not just
	// the stored private key being RSA.
	block, _ := pem.Decode([]byte(*c.CertPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("certificate public key is %T, want RSA", leaf.PublicKey)
	}
	assertKeyMatchesCert(t, c.KeyPEM, *c.CertPEM)
}

func TestBuildCSRExtendedKeyUsage(t *testing.T) {
	signer, _, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}

	der, err := BuildCSR(signer, []string{"a.example.com"}, "serverAuth,clientAuth")
	if err != nil {
		t.Fatalf("BuildCSR with EKU = %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "a.example.com" {
		t.Errorf("SANs = %v, want the domain preserved", csr.DNSNames)
	}
	var hasEKU bool
	for _, ext := range csr.Extensions {
		if ext.Id.String() == "2.5.29.37" {
			hasEKU = true
		}
	}
	if !hasEKU {
		t.Error("the CSR carries no extended key usage extension")
	}

	if _, err := BuildCSR(signer, []string{"a.example.com"}, "nonsense"); err == nil {
		t.Error("BuildCSR accepted an unknown extended key usage")
	}
}
