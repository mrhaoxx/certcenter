// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"

	"github.com/mholt/acmez/v3/acme"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// RevocationReasons are the RFC 5280 codes an ACME server accepts, keyed
// by the name shown in the UI.
//
// Let's Encrypt only honours a subset — unspecified, keyCompromise,
// superseded and cessationOfOperation — and rejects the rest; the others
// are listed because other CAs take them.
var RevocationReasons = map[string]int{
	"unspecified":          acme.ReasonUnspecified,
	"keyCompromise":        acme.ReasonKeyCompromise,
	"affiliationChanged":   acme.ReasonAffiliationChanged,
	"superseded":           acme.ReasonSuperseded,
	"cessationOfOperation": acme.ReasonCessationOfOperation,
}

// RevocationReasonNames lists the reasons for API validation and the UI.
func RevocationReasonNames() []string {
	return []string{"unspecified", "keyCompromise", "superseded",
		"cessationOfOperation", "affiliationChanged"}
}

// Revoke asks the CA to revoke a certificate.
//
// The certificate's own key signs the request, which is what lets a
// revocation succeed even when the ACME account that issued it is gone —
// and it is the path that matters most, since the reason to revoke in a
// hurry is usually that this key leaked.
func (is *Issuer) Revoke(ctx context.Context, certID int64, reasonName string) error {
	reason, ok := RevocationReasons[reasonName]
	if !ok {
		return fmt.Errorf("unknown revocation reason %q", reasonName)
	}

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}
	if cert.CertPEM == nil || *cert.CertPEM == "" {
		return fmt.Errorf("this certificate has never been issued, so there is nothing to revoke")
	}

	block, _ := pem.Decode([]byte(*cert.CertPEM))
	if block == nil {
		return fmt.Errorf("the stored certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse the stored certificate: %w", err)
	}

	certKey, err := ParseCertKey(cert.KeyPEM)
	if err != nil {
		return fmt.Errorf("the stored private key is unusable, so the CA cannot be asked to revoke: %w", err)
	}

	acct, err := is.Store.GetACMEAccount(ctx, cert.ACMEAccountID)
	if err != nil {
		return err
	}
	accountSigner, err := ParseAccountKey(acct.PrivateKeyPEM)
	if err != nil {
		return err
	}
	account := acme.Account{PrivateKey: accountSigner}
	if acct.AccountURL != nil {
		account.Location = *acct.AccountURL
	}
	client := &acme.Client{
		Directory:  acct.DirectoryURL,
		HTTPClient: is.HTTPClient,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := client.RevokeCertificate(ctx, account, leaf, certKey, reason); err != nil {
		return fmt.Errorf("the CA rejected the revocation: %w", err)
	}

	if err := is.Store.MarkRevoked(ctx, certID, reasonName); err != nil {
		return fmt.Errorf("the certificate was revoked at the CA but could not be marked locally: %w", err)
	}
	_ = is.Store.AppendLog(ctx, db.OperationLog{
		Action: "revoke", ResourceType: "certificate", ResourceID: &certID,
		Detail: &reasonName, Operator: "admin",
	})
	return nil
}
