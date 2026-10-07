// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestChangeACMEAccount(t *testing.T) {
	// Moving a certificate between CAs — staging to production, or one
	// issuer to another — should not mean recreating it and losing its
	// history. The certificate in hand is unaffected; the next issuance
	// goes to the new account.
	srv, certID := newServerWithIssuedCertificate(t)
	ctx := context.Background()

	other, err := srv.DB.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "production", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
		Email: "a@b.c", PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, http.MethodPatch, "/api/certificates/"+itoa64(certID),
		`{"acmeAccountId":`+itoa64(other)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}

	c, err := srv.DB.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if c.ACMEAccountID != other {
		t.Errorf("account = %d, want %d", c.ACMEAccountID, other)
	}
	// The issued material belongs to whoever signed it and must survive.
	if c.CertPEM == nil || *c.CertPEM == "" {
		t.Error("the certificate was discarded by an account change")
	}
}

func TestChangeACMEAccountRejectsUnknown(t *testing.T) {
	srv, certID := newServerWithIssuedCertificate(t)
	rec := authed(t, srv, http.MethodPatch, "/api/certificates/"+itoa64(certID),
		`{"acmeAccountId":9999}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestChangeDNSProviders(t *testing.T) {
	srv, certID := newServerWithIssuedCertificate(t)
	ctx := context.Background()

	second, err := srv.DB.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "ali", Kind: "aliyun",
		Config: `{"access_key_id":"k","access_key_secret":"s","domain":"example.net"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	rec := authed(t, srv, http.MethodPatch, "/api/certificates/"+itoa64(certID),
		`{"dnsProviderIds":[1,`+itoa64(second)+`]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}

	providers, err := srv.DB.ListCertificateDNSProviders(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) != 2 {
		t.Errorf("providers = %d, want both attached", len(providers))
	}
}

func TestClearingEveryDNSProviderIsRefused(t *testing.T) {
	// A certificate with no provider can never be issued, and failing here
	// beats failing at the first challenge weeks later.
	srv, certID := newServerWithIssuedCertificate(t)
	rec := authed(t, srv, http.MethodPatch, "/api/certificates/"+itoa64(certID),
		`{"dnsProviderIds":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
