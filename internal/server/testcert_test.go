// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// newServerWithIssuedCertificate returns a server holding one certificate
// with real material: a leaf signed by a throwaway CA, that CA as the
// chain, and the leaf's key. Handlers that parse or re-encode the stored
// PEM need something genuine rather than a placeholder string.
func newServerWithIssuedCertificate(t *testing.T) (*Server, int64) {
	t.Helper()
	srv := newTestServer(t)
	certID := seedCertificateRow(t, srv)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	toPEM := func(kind string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
	}
	store := srv.DB.(*db.SQLite)
	if _, err := store.DB.Exec(`UPDATE certificates
		SET status='issued', cert_pem=?, chain_pem=?, key_pem=?,
		    not_before=datetime('now','-1 hour'), not_after=datetime('now','+1 day')
		WHERE id=?`,
		toPEM("CERTIFICATE", leafDER), toPEM("CERTIFICATE", caDER),
		toPEM("PRIVATE KEY", keyDER), certID); err != nil {
		t.Fatal(err)
	}
	return srv, certID
}

// newServerWithPendingCertificate returns a certificate that was never
// issued, for the paths that must refuse one.
func newServerWithPendingCertificate(t *testing.T) (*Server, int64) {
	t.Helper()
	srv := newTestServer(t)
	return srv, seedCertificateRow(t, srv)
}

func seedCertificateRow(t *testing.T, srv *Server) int64 {
	t.Helper()
	ctx := context.Background()
	acctID, err := srv.DB.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "le", DirectoryURL: "https://acme.example/dir", Email: "a@b.c",
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := srv.DB.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "cf", Kind: "cloudflare", Config: `{"api_token":"t","zone_id":"z"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	certID, err := srv.DB.CreateCertificate(ctx, db.Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certID
}
