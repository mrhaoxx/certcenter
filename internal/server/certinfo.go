// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"
)

// CertInfo is the parsed view of one certificate for the detail page.
type CertInfo struct {
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	SerialNumber       string   `json:"serialNumber"`
	NotBefore          string   `json:"notBefore"`
	NotAfter           string   `json:"notAfter"`
	SignatureAlgorithm string   `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm"`
	PublicKeyBits      int      `json:"publicKeyBits"`
	Version            int      `json:"version"`
	SubjectAltNames    []string `json:"subjectAltNames"`
	KeyUsage           []string `json:"keyUsage"`
	ExtendedKeyUsage   []string `json:"extendedKeyUsage"`
	IsCA               bool     `json:"isCa"`
	AuthorityKeyID     string   `json:"authorityKeyId"`
	SubjectKeyID       string   `json:"subjectKeyId"`
	OCSPServers        []string `json:"ocspServers"`
	IssuingURLs        []string `json:"issuingUrls"`
	CRLDistribution    []string `json:"crlDistributionPoints"`
	FingerprintSHA256  string   `json:"fingerprintSha256"`
	FingerprintSHA1    string   `json:"fingerprintSha1"`
	PEM                string   `json:"pem"`
}

// x509Response carries the leaf plus the intermediates that lead to it.
type x509Response struct {
	Leaf  CertInfo   `json:"leaf"`
	Chain []CertInfo `json:"chain"`
}

func (s *Server) handleCertificateX509(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	if cert.CertPEM == nil || *cert.CertPEM == "" {
		s.writeErr(w, http.StatusConflict, "NOT_ISSUED",
			"the certificate has not been issued yet", nil)
		return
	}

	leaf, err := parseFirstPEM(*cert.CertPEM)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "PARSE_ERROR",
			"the stored certificate could not be parsed", err.Error())
		return
	}

	resp := x509Response{Leaf: describeCert(leaf), Chain: []CertInfo{}}
	// cert_pem holds the leaf alone and chain_pem the intermediates, so the
	// chain never repeats the leaf — the Rust view listed it twice because
	// both columns held the whole chain.
	if cert.ChainPEM != nil {
		for _, c := range parseAllPEM(*cert.ChainPEM) {
			resp.Chain = append(resp.Chain, describeCert(c))
		}
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func parseFirstPEM(s string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseAllPEM(s string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func describeCert(c *x509.Certificate) CertInfo {
	sha256Sum := sha256.Sum256(c.Raw)
	sha1Sum := sha1.Sum(c.Raw)

	info := CertInfo{
		Subject:            c.Subject.String(),
		Issuer:             c.Issuer.String(),
		SerialNumber:       fmt.Sprintf("%X", c.SerialNumber),
		NotBefore:          c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           c.NotAfter.UTC().Format(time.RFC3339),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		PublicKeyBits:      publicKeyBits(c),
		Version:            c.Version,
		SubjectAltNames:    subjectAltNames(c),
		KeyUsage:           keyUsageNames(c.KeyUsage),
		ExtendedKeyUsage:   extKeyUsageNames(c),
		IsCA:               c.IsCA,
		OCSPServers:        orEmpty(c.OCSPServer),
		IssuingURLs:        orEmpty(c.IssuingCertificateURL),
		CRLDistribution:    orEmpty(c.CRLDistributionPoints),
		FingerprintSHA256:  hex.EncodeToString(sha256Sum[:]),
		FingerprintSHA1:    hex.EncodeToString(sha1Sum[:]),
		PEM:                string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
	if len(c.AuthorityKeyId) > 0 {
		info.AuthorityKeyID = hex.EncodeToString(c.AuthorityKeyId)
	}
	if len(c.SubjectKeyId) > 0 {
		info.SubjectKeyID = hex.EncodeToString(c.SubjectKeyId)
	}
	return info
}

// publicKeyBits reports the key size. The Rust implementation multiplied
// the SPKI byte length by eight, which counts the DER wrapper and so was
// only ever approximate.
func publicKeyBits(c *x509.Certificate) int {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return len(pub) * 8
	default:
		return 0
	}
}

func subjectAltNames(c *x509.Certificate) []string {
	out := []string{}
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	return out
}

func keyUsageNames(u x509.KeyUsage) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "Digital Signature"},
		{x509.KeyUsageContentCommitment, "Non Repudiation"},
		{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{x509.KeyUsageKeyAgreement, "Key Agreement"},
		{x509.KeyUsageCertSign, "Certificate Sign"},
		{x509.KeyUsageCRLSign, "CRL Sign"},
		{x509.KeyUsageEncipherOnly, "Encipher Only"},
		{x509.KeyUsageDecipherOnly, "Decipher Only"},
	}
	out := []string{}
	for _, n := range names {
		if u&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageNames(c *x509.Certificate) []string {
	labels := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "Any",
		x509.ExtKeyUsageServerAuth:      "Server Authentication",
		x509.ExtKeyUsageClientAuth:      "Client Authentication",
		x509.ExtKeyUsageCodeSigning:     "Code Signing",
		x509.ExtKeyUsageEmailProtection: "Email Protection",
		x509.ExtKeyUsageTimeStamping:    "Time Stamping",
		x509.ExtKeyUsageOCSPSigning:     "OCSP Signing",
	}
	out := []string{}
	for _, u := range c.ExtKeyUsage {
		if label, ok := labels[u]; ok {
			out = append(out, label)
			continue
		}
		out = append(out, fmt.Sprintf("Unknown (%d)", u))
	}
	for _, oid := range c.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
