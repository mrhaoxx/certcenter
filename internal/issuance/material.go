// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/mholt/acmez/v3"
)

// Key algorithms a certificate can be issued with. The names match
// acme.sh's -k values so an operator moving over recognises them.
const (
	KeyTypeEC256   = "ec-256"
	KeyTypeEC384   = "ec-384"
	KeyTypeEC521   = "ec-521"
	KeyTypeRSA2048 = "rsa-2048"
	KeyTypeRSA3072 = "rsa-3072"
	KeyTypeRSA4096 = "rsa-4096"
)

// DefaultKeyType is what was hard-coded before this became a choice.
const DefaultKeyType = KeyTypeEC256

// KeyTypes lists the supported algorithms for API validation and the UI.
func KeyTypes() []string {
	return []string{KeyTypeEC256, KeyTypeEC384, KeyTypeEC521,
		KeyTypeRSA2048, KeyTypeRSA3072, KeyTypeRSA4096}
}

// GenerateCertKey returns a fresh key of the requested algorithm together
// with its PKCS#8 PEM encoding for storage.
//
// ECDSA is smaller and faster and is the right default, but some load
// balancers, CDN edges and older Java stacks still only accept RSA — with
// only ec-256 available those targets cannot be served at all.
func GenerateCertKey(keyType string) (crypto.Signer, string, error) {
	if keyType == "" {
		keyType = DefaultKeyType
	}
	var (
		key crypto.Signer
		err error
	)
	switch keyType {
	case KeyTypeEC256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeEC384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeEC521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case KeyTypeRSA2048:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA3072:
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	case KeyTypeRSA4096:
		key, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, "", fmt.Errorf("unsupported key type %q", keyType)
	}
	if err != nil {
		return nil, "", fmt.Errorf("generate certificate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal certificate key: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// DescribeKey names the algorithm of a stored key, for the timeline.
func DescribeKey(signer crypto.Signer) string {
	switch k := signer.Public().(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", k)
	}
}

// BuildCSR produces a signed CSR (DER) covering domains, with an empty
// subject — the CN field is deprecated for domain validation, so the names
// live only in the SAN extension.
//
// acmez.NewCSR does the work because it normalizes internationalized names
// to punycode, which a hand-rolled template silently gets wrong.
// ExtendedKeyUsages maps the names accepted in configuration onto x509
// values. acme.sh's default is serverAuth,clientAuth.
var ExtendedKeyUsages = map[string]x509.ExtKeyUsage{
	"serverAuth":      x509.ExtKeyUsageServerAuth,
	"clientAuth":      x509.ExtKeyUsageClientAuth,
	"codeSigning":     x509.ExtKeyUsageCodeSigning,
	"emailProtection": x509.ExtKeyUsageEmailProtection,
	"timeStamping":    x509.ExtKeyUsageTimeStamping,
	"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
}

// BuildCSR builds the request. eku is a comma-separated list of names from
// ExtendedKeyUsages; empty leaves the extension out.
//
// Public CAs largely decide extended key usage themselves and ignore what
// the CSR asks for, so this changes what is requested, not necessarily
// what comes back.
func BuildCSR(signer crypto.Signer, domains []string, eku string) ([]byte, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains to request")
	}
	csr, err := acmez.NewCSR(signer, domains)
	if err != nil {
		return nil, fmt.Errorf("build CSR: %w", err)
	}
	if eku == "" {
		return csr.Raw, nil
	}

	usages, err := ParseExtendedKeyUsage(eku)
	if err != nil {
		return nil, err
	}
	// acmez builds and signs in one step, so requesting a different EKU
	// means rebuilding the template and re-signing.
	tmpl := &x509.CertificateRequest{
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		ExtraExtensions:    ekuExtension(usages),
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		return nil, fmt.Errorf("build CSR with extended key usage: %w", err)
	}
	return der, nil
}

// ParseExtendedKeyUsage turns a comma-separated list into x509 values.
func ParseExtendedKeyUsage(eku string) ([]x509.ExtKeyUsage, error) {
	var out []x509.ExtKeyUsage
	for _, name := range strings.Split(eku, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		u, ok := ExtendedKeyUsages[name]
		if !ok {
			return nil, fmt.Errorf("unknown extended key usage %q", name)
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, errors.New("no usable extended key usage given")
	}
	return out, nil
}

func ekuExtension(usages []x509.ExtKeyUsage) []pkix.Extension {
	oids := make([]asn1.ObjectIdentifier, 0, len(usages))
	for _, u := range usages {
		if oid, ok := ekuOID(u); ok {
			oids = append(oids, oid)
		}
	}
	der, err := asn1.Marshal(oids)
	if err != nil {
		return nil
	}
	return []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: der}}
}

func ekuOID(u x509.ExtKeyUsage) (asn1.ObjectIdentifier, bool) {
	switch u {
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}, true
	case x509.ExtKeyUsageClientAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}, true
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}, true
	case x509.ExtKeyUsageEmailProtection:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}, true
	case x509.ExtKeyUsageTimeStamping:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}, true
	case x509.ExtKeyUsageOCSPSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}, true
	}
	return nil, false
}

// ChainIssuerCN reports the Common Name of the certificate that signed the
// leaf, which is how a preferred chain is selected.
func ChainIssuerCN(chainPEM []byte) (string, error) {
	leafPEM, _, leaf, err := SplitChain(chainPEM)
	if err != nil {
		return "", err
	}
	_ = leafPEM
	return leaf.Issuer.CommonName, nil
}

// SplitChain separates a CA-returned PEM chain into the leaf and the
// intermediates, and parses the leaf.
//
// Keeping them apart matters: the Rust implementation stored the whole
// chain in both cert_pem and chain_pem, so the detail view listed the leaf
// twice and the config-center deploy pushed the chain duplicated.
func SplitChain(chainPEM []byte) (string, string, *x509.Certificate, error) {
	var leafPEM string
	var leaf *x509.Certificate
	var rest strings.Builder

	remaining := chainPEM
	for i := 0; ; i++ {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", "", nil, fmt.Errorf("chain contains a %q block, want CERTIFICATE", block.Type)
		}
		encoded := string(pem.EncodeToMemory(block))
		if i == 0 {
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", "", nil, fmt.Errorf("parse leaf certificate: %w", err)
			}
			leaf, leafPEM = parsed, encoded
			continue
		}
		rest.WriteString(encoded)
	}
	if leaf == nil {
		return "", "", nil, errors.New("chain contains no certificate")
	}
	return leafPEM, rest.String(), leaf, nil
}

// ParseCertKey loads a stored certificate private key.
//
// Renewal reuses the key by default, so this is the path a renewal takes
// every time; a parse failure has to stop the run rather than fall back to
// generating a new one, because silently rotating would break whatever was
// pinning the old public key.
func ParseCertKey(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("the stored private key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the stored private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("the stored private key of type %T cannot sign", key)
	}
	return signer, nil
}

// IdentifierType reports the ACME identifier type for a name: "ip" for a
// bare address, "dns" otherwise.
func IdentifierType(value string) string {
	if net.ParseIP(value) != nil {
		return "ip"
	}
	return "dns"
}

// SplitIdentifiers separates a list into DNS names and IP addresses, which
// is what a CSR needs them as.
func SplitIdentifiers(values []string) (dnsNames []string, ips []net.IP) {
	for _, v := range values {
		if ip := net.ParseIP(v); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dnsNames = append(dnsNames, v)
	}
	return dnsNames, ips
}

// ParseCSR validates a caller-supplied certificate request and returns its
// DER for the ACME order.
//
// The names in the CSR must be exactly the names being ordered. A CSR
// asking for something else would either be refused by the CA or, worse,
// yield a certificate for names nobody meant to request.
func ParseCSR(csrPEM string, domains []string) ([]byte, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("the CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the CSR's signature does not verify: %w", err)
	}

	want := map[string]bool{}
	for _, d := range domains {
		want[strings.ToLower(d)] = true
	}
	got := map[string]bool{}
	for _, n := range csr.DNSNames {
		got[strings.ToLower(n)] = true
	}
	for _, ip := range csr.IPAddresses {
		got[ip.String()] = true
	}

	for name := range want {
		if !got[name] {
			return nil, fmt.Errorf("the CSR does not cover %q", name)
		}
	}
	for name := range got {
		if !want[name] {
			return nil, fmt.Errorf("the CSR asks for %q, which this certificate does not order", name)
		}
	}
	return block.Bytes, nil
}
