// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/issuance"
)

type pkcs12Request struct {
	Password string `json:"password"`
}

// handleCertificatePKCS12 exports the certificate, its chain and its key as
// a PKCS#12 archive.
//
// PEM is what everything on Unix wants and it is all this served before.
// Windows, IIS and Java keystores want a .pfx, and converting one by hand
// means running openssl over a private key on somebody's laptop.
func (s *Server) handleCertificatePKCS12(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req pkcs12Request
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	// PKCS#12 permits an empty password, but an archive holding a private
	// key should not travel without one.
	if len(req.Password) < 4 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"the export password must be at least 4 characters", nil)
		return
	}

	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	if cert.CertPEM == nil || *cert.CertPEM == "" || cert.KeyPEM == "" {
		s.writeErr(w, http.StatusConflict, "NOT_ISSUED",
			"this certificate has not been issued yet", nil)
		return
	}

	leaf, chain, err := parseForPKCS12(cert)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", err.Error(), nil)
		return
	}
	key, err := issuance.ParseCertKey(cert.KeyPEM)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL",
			"the stored private key is unusable", nil)
		return
	}

	// Modern encodes with AES rather than the RC2/3DES of the legacy
	// profile, which current OpenSSL refuses to read without -legacy.
	archive, err := pkcs12.Modern.Encode(key, leaf, chain, req.Password)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL",
			"could not build the PKCS#12 archive", err.Error())
		return
	}

	name := strings.ReplaceAll(cert.Domain, "*", "wildcard") + ".pfx"
	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(archive)

	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "export_pkcs12", ResourceType: "certificate", ResourceID: &id,
		Operator: "admin",
	})
}

// parseForPKCS12 decodes the stored leaf and chain into x509 values.
func parseForPKCS12(cert *db.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(*cert.CertPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("the stored certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse the stored certificate: %w", err)
	}

	var chain []*x509.Certificate
	if cert.ChainPEM != nil {
		rest := []byte(*cert.ChainPEM)
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("parse an intermediate: %w", err)
			}
			chain = append(chain, c)
		}
	}
	return leaf, chain, nil
}
