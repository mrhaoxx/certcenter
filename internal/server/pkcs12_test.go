// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto"
	"net/http"
	"testing"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestPKCS12ExportRoundTrips(t *testing.T) {
	// An archive nobody can open is not an export. Decode it back with an
	// independent reader and check the key still matches the certificate.
	srv, certID := newServerWithIssuedCertificate(t)

	rec := authed(t, srv, http.MethodPost, "/api/certificates/"+itoa64(certID)+"/pkcs12",
		`{"password":"export-pass"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-pkcs12" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("the response is cacheable; it contains a private key")
	}

	key, leaf, chain, err := pkcs12.DecodeChain(rec.Body.Bytes(), "export-pass")
	if err != nil {
		t.Fatalf("the exported archive does not decode: %v", err)
	}
	if key == nil || leaf == nil {
		t.Fatal("the archive is missing the key or the certificate")
	}
	if len(chain) == 0 {
		t.Error("the archive carries no intermediates; clients would see an incomplete chain")
	}
	// The key has to belong to the certificate, or the archive installs but
	// no handshake completes.
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatalf("the archive's key is %T and cannot sign", key)
	}
	if !leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(signer.Public()) {
		t.Error("the archive's key does not match its certificate")
	}
}

func TestPKCS12RejectsWeakPassword(t *testing.T) {
	srv, certID := newServerWithIssuedCertificate(t)
	rec := authed(t, srv, http.MethodPost, "/api/certificates/"+itoa64(certID)+"/pkcs12", `{"password":"ab"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestPKCS12RequiresAnIssuedCertificate(t *testing.T) {
	srv, certID := newServerWithPendingCertificate(t)
	rec := authed(t, srv, http.MethodPost, "/api/certificates/"+itoa64(certID)+"/pkcs12",
		`{"password":"export-pass"}`)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409 for a certificate that was never issued", rec.Code)
	}
}

func TestPKCS12RequiresSession(t *testing.T) {
	srv, certID := newServerWithIssuedCertificate(t)
	rec := postJSON(t, srv, "/api/certificates/"+itoa64(certID)+"/pkcs12", `{"password":"export-pass"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
