// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package issuance obtains certificates over ACME DNS-01, driving the
// protocol state machine step by step so every phase lands in the run's
// event timeline.
package issuance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mholt/acmez/v3/acme"
)

// GenerateAccountKey returns a fresh ECDSA P-256 key as PKCS#8 PEM.
//
// PKCS#8 PEM is deliberately a portable format: the Rust implementation
// stored instant-acme's bespoke JSON credential blob, which nothing else
// can read. A PEM key can be moved between certbot, lego and us.
func GenerateAccountKey() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal account key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseAccountKey decodes a PKCS#8 PEM private key.
func ParseAccountKey(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("account key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("account key of type %T cannot sign", key)
	}
	return signer, nil
}

// Registrar creates and validates accounts at a CA.
type Registrar struct {
	// HTTPClient overrides the transport, which the tests use to trust the
	// in-process Pebble CA's self-signed certificate.
	HTTPClient *http.Client
}

func (r *Registrar) client(directoryURL string) *acme.Client {
	return &acme.Client{
		Directory:  directoryURL,
		HTTPClient: r.HTTPClient,
		// The protocol library's own logging is discarded: our timeline
		// comes from explicit AppendEvent calls, not from scraped log
		// lines. This is the property lego could not provide — its logger
		// is a process-global, so concurrent issuances interleave.
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// Registration describes an account to create at a CA.
type Registration struct {
	DirectoryURL string
	Email        string
	KeyPEM       string

	// EABKeyID and EABMACKey bind the new ACME account to an existing
	// account at the CA. Some CAs — ZeroSSL, Google Trust Services,
	// Sectigo — reject newAccount without them, answering
	// urn:ietf:params:acme:error:externalAccountRequired. Let's Encrypt
	// does not use them, so both stay empty there.
	EABKeyID  string
	EABMACKey string
}

// RequiresEAB reports whether a CA rejected the registration because it
// needs external account binding, so callers can say so specifically
// instead of relaying a raw protocol error.
func RequiresEAB(err error) bool {
	return err != nil && strings.Contains(err.Error(), "externalAccountRequired")
}

// Register creates a new account at the CA and returns its URL (the ACME
// "kid"). Terms of service are accepted on the operator's behalf, matching
// the Rust implementation's behaviour.
func (r *Registrar) Register(ctx context.Context, reg Registration) (string, error) {
	signer, err := ParseAccountKey(reg.KeyPEM)
	if err != nil {
		return "", err
	}
	account := acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           signer,
	}
	if reg.Email != "" {
		account.Contact = []string{"mailto:" + reg.Email}
	}

	client := r.client(reg.DirectoryURL)
	if reg.EABKeyID != "" || reg.EABMACKey != "" {
		if reg.EABKeyID == "" || reg.EABMACKey == "" {
			return "", fmt.Errorf("external account binding needs both a key ID and a MAC key")
		}
		macKey, err := normalizeEABMACKey(reg.EABMACKey)
		if err != nil {
			return "", err
		}
		// The binding is a JWS over the account key, signed with the MAC
		// key and addressed to this directory's newAccount URL, so it can
		// only be built once the directory is known.
		err = account.SetExternalAccountBinding(ctx, client, acme.EAB{
			KeyID:  reg.EABKeyID,
			MACKey: macKey,
		})
		if err != nil {
			return "", fmt.Errorf("build external account binding: %w", err)
		}
	}

	registered, err := client.NewAccount(ctx, account)
	if err != nil {
		return "", fmt.Errorf("register ACME account: %w", err)
	}
	return registered.Location, nil
}

// Verify checks that an imported (key, account URL) pair is live at the CA,
// so a bad import fails at save time rather than at the first issuance.
func (r *Registrar) Verify(ctx context.Context, directoryURL, accountURL, keyPEM string) error {
	signer, err := ParseAccountKey(keyPEM)
	if err != nil {
		return err
	}
	_, err = r.client(directoryURL).GetAccount(ctx, acme.Account{
		Location:   accountURL,
		PrivateKey: signer,
	})
	if err != nil {
		return fmt.Errorf("verify ACME account: %w", err)
	}
	return nil
}

// Capabilities is what a CA's directory says about itself.
//
// Reading these instead of hard-coding them per CA keeps the UI honest: a
// CA can start or stop requiring external account binding, or change which
// profiles it offers, without us shipping a release.
type Capabilities struct {
	// RequiresEAB mirrors the directory's externalAccountRequired.
	RequiresEAB bool `json:"requiresEab"`
	// Profiles maps a profile name to its description. On Let's Encrypt a
	// profile also decides the lifetime; on Google Trust Services it only
	// shapes the certificate's contents.
	Profiles map[string]string `json:"profiles"`
	// TermsOfService and Website are shown so an operator can check what
	// they are agreeing to before registering.
	TermsOfService string `json:"termsOfService"`
	Website        string `json:"website"`
}

// Probe reads a CA's directory and reports what it advertises.
func (r *Registrar) Probe(ctx context.Context, directoryURL string) (Capabilities, error) {
	var c Capabilities
	dir, err := r.client(directoryURL).GetDirectory(ctx)
	if err != nil {
		return c, fmt.Errorf("fetch the CA directory: %w", err)
	}
	c.Profiles = map[string]string{}
	if dir.Meta == nil {
		return c, nil
	}
	c.RequiresEAB = dir.Meta.ExternalAccountRequired
	c.TermsOfService = dir.Meta.TermsOfService
	c.Website = dir.Meta.Website
	if dir.Meta.Profiles != nil {
		c.Profiles = dir.Meta.Profiles
	}
	return c, nil
}

// Profiles reports just the advertised profiles, for callers that have an
// account already.
func (r *Registrar) Profiles(ctx context.Context, directoryURL string) (map[string]string, error) {
	c, err := r.Probe(ctx, directoryURL)
	if err != nil {
		return nil, err
	}
	return c.Profiles, nil
}

// normalizeEABMACKey converts a CA-issued MAC key into the unpadded
// base64url form acmez expects.
//
// CAs are not consistent: Google's gcloud prints a b64MacKey, ZeroSSL
// shows one in its console, and operators paste them with or without "="
// padding and occasionally in the standard alphabet with "+" and "/".
// acmez decodes strictly as unpadded base64url, so anything else fails
// with "base64-decoding MAC key" — an error that says nothing about the
// real problem being a paste format.
func normalizeEABMACKey(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", fmt.Errorf("the EAB MAC key is empty")
	}
	// Translate the standard alphabet to the URL-safe one, then strip
	// padding; the two alphabets differ only in these two characters.
	key = strings.ReplaceAll(key, "+", "-")
	key = strings.ReplaceAll(key, "/", "_")
	key = strings.TrimRight(key, "=")

	decoded, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("the EAB MAC key is not valid base64: %w", err)
	}
	if len(decoded) == 0 {
		return "", fmt.Errorf("the EAB MAC key decodes to nothing")
	}
	return key, nil
}
