// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestBuildCSR(t *testing.T) {
	signer, _, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}
	domains := []string{"example.com", "*.example.com"}
	der, err := BuildCSR(signer, domains, "")
	if err != nil {
		t.Fatal(err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("the CSR we produced does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	// 空 Subject：CN 已被弃用于域名验证，域名只走 SAN。
	if got := csr.Subject.String(); got != "" {
		t.Errorf("Subject = %q, want empty", got)
	}
	if len(csr.DNSNames) != 2 {
		t.Fatalf("DNSNames = %v, want two entries", csr.DNSNames)
	}
	for _, want := range domains {
		found := false
		for _, got := range csr.DNSNames {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("DNSNames = %v, missing %q", csr.DNSNames, want)
		}
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA256", csr.SignatureAlgorithm)
	}
}

func TestBuildCSRNormalizesUnicodeDomains(t *testing.T) {
	// 国际化域名必须以 punycode 进证书。自己拼 CSR 模板容易漏掉这步，
	// 所以底层用 acmez.NewCSR。
	signer, _, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := BuildCSR(signer, []string{"例え.テスト"}, "")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) != 1 {
		t.Fatalf("DNSNames = %v", csr.DNSNames)
	}
	if !strings.HasPrefix(csr.DNSNames[0], "xn--") {
		t.Errorf("DNSNames[0] = %q, want a punycode (xn--) form", csr.DNSNames[0])
	}
}

func TestBuildCSRRejectsNoDomains(t *testing.T) {
	signer, _, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCSR(signer, nil, ""); err == nil {
		t.Error("BuildCSR with no domains = nil error, want failure")
	}
}

func TestGenerateCertKeyPEMRoundTrips(t *testing.T) {
	signer, pemStr, err := GenerateCertKey(KeyTypeEC256)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("PEM header = %q, want PKCS#8", pemStr[:30])
	}
	back, err := ParseAccountKey(pemStr) // same PKCS#8 parser
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := back.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("parsed public key is %T, want *ecdsa.PublicKey", back.Public())
	}
	if !pub.Equal(signer.Public()) {
		t.Error("the parsed key's public part differs from the generated one")
	}
}

func TestSplitChain(t *testing.T) {
	// Rust 版把整条链同时写进 cert_pem 和 chain_pem，导致详情页把叶子
	// 显示两遍、配置中心推重复的链。这里必须按 PEM 块切开。
	chain := testChainPEM(t)

	leafPEM, restPEM, leaf, err := SplitChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(leafPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("leafPEM holds %d certificates, want exactly 1",
			strings.Count(leafPEM, "BEGIN CERTIFICATE"))
	}
	if strings.Count(restPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("restPEM holds %d certificates, want the single intermediate",
			strings.Count(restPEM, "BEGIN CERTIFICATE"))
	}
	if leafPEM == restPEM {
		t.Error("leafPEM equals restPEM; nothing was actually split")
	}
	if leaf == nil {
		t.Fatal("SplitChain returned a nil leaf")
	}
	if len(leaf.DNSNames) == 0 {
		t.Error("the parsed leaf has no SANs")
	}
	if leaf.NotAfter.Before(leaf.NotBefore) {
		t.Error("leaf NotAfter precedes NotBefore")
	}
}

func TestSplitChainSingleCertificate(t *testing.T) {
	// 有些 CA 只回叶子。此时 restPEM 为空且不应报错。
	full := string(testChainPEM(t))
	end := strings.Index(full, "-----END CERTIFICATE-----")
	onlyLeaf := full[:end+len("-----END CERTIFICATE-----")+1]

	leafPEM, restPEM, leaf, err := SplitChain([]byte(onlyLeaf))
	if err != nil {
		t.Fatalf("SplitChain on a lone leaf = %v", err)
	}
	if restPEM != "" {
		t.Errorf("restPEM = %q, want empty", restPEM)
	}
	if leaf == nil || leafPEM == "" {
		t.Error("the leaf must still be returned")
	}
}

func TestSplitChainRejectsGarbage(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"非 PEM", []byte("hello")},
		{"PEM 但不是证书", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := SplitChain(tt.in); err == nil {
				t.Error("SplitChain = nil error, want failure")
			}
		})
	}
}

// testChainPEM builds a two-certificate chain locally, so the split logic
// is unit-testable without a CA. That real CA bytes also split correctly is
// asserted by TestIssueEndToEnd.
func testChainPEM(t *testing.T) []byte {
	t.Helper()
	leaf := selfSigned(t, "example.com", true)
	inter := selfSigned(t, "intermediate.example", false)
	var b strings.Builder
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter}))
	return []byte(b.String())
}

func selfSigned(t *testing.T, dnsName string, isLeaf bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if isLeaf {
		tmpl.DNSNames = []string{dnsName}
	} else {
		tmpl.Subject.CommonName = dnsName
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

var _ crypto.Signer = (*ecdsa.PrivateKey)(nil)
