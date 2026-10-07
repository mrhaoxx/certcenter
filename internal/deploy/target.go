// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package deploy installs an issued certificate wherever it is needed:
// over SSH, to a webhook, to a CDN, or into the ServerAgent config center.
package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CertificateData is the material handed to every target.
type CertificateData struct {
	Domain   string
	CertPEM  string // leaf only
	KeyPEM   string
	ChainPEM string // intermediates only
}

// FullChainPEM is leaf followed by intermediates, which is what most
// servers want configured. It is assembled here rather than stored that
// way because cert_pem and chain_pem are kept separate (spec §14).
func (c CertificateData) FullChainPEM() string {
	if c.ChainPEM == "" {
		return c.CertPEM
	}
	leaf := c.CertPEM
	if len(leaf) > 0 && leaf[len(leaf)-1] != '\n' {
		leaf += "\n"
	}
	return leaf + c.ChainPEM
}

// Material a step can write. These names appear in stored step configs.
const (
	SourceCertificate = "certificate"
	SourcePrivateKey  = "private_key"
	SourceChain       = "chain"
	SourceFullChain   = "fullchain"
)

// Event is one entry of a deployment's timeline. Level mirrors db's
// info/success/error.
type Event struct {
	Type    string
	Message string
	Detail  string
	Level   string
}

// Target installs a certificate somewhere.
//
// Events are returned alongside the error rather than instead of it: a
// failed deployment's timeline is exactly the part an operator needs, so
// it must be persisted either way.
type Target interface {
	Deploy(ctx context.Context, cert *CertificateData) ([]Event, error)
}

// KindPipeline is the only target kind.
//
// There used to be five — ssh, webhook, configcenter and the two CDNs —
// and a target could be exactly one of them. That did not match how
// certificates are actually installed: write the file, tell the config
// center, poke a reload endpoint, check the result. Each of the old kinds
// is now a step, and every target is an ordered list of them.
const KindPipeline = "pipeline"

// Kinds lists the supported target kinds for API validation and the UI.
func Kinds() []string {
	return []string{KindPipeline}
}

// Options carries values the application injects into a target that the
// operator does not configure per-target.
type Options struct {
	// ManagementURL is the config center's management WebSocket, taken
	// from the app's [bus] config rather than from the target's own JSON.
	ManagementURL string
}

// New builds a target from its stored kind and JSON config.
func New(kind, configJSON string, opts Options) (Target, error) {
	if kind != KindPipeline {
		return nil, fmt.Errorf(
			"unsupported deploy target kind %q; every target is a %q now, "+
				"with what used to be a kind available as a step", kind, KindPipeline)
	}
	return newPipeline(configJSON, opts)
}

// decodeConfig unmarshals a target config, rejecting unknown keys so a
// mistyped field fails at save time instead of silently doing nothing.
func decodeConfig(configJSON string, dst any) error {
	if configJSON == "" {
		configJSON = "{}"
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(configJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse deploy target config: %w", err)
	}
	return nil
}

// httpClient is shared by the HTTP-based targets. Every outbound call is
// bounded; the Rust implementation set no timeouts at all.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// truncate bounds a value copied into an event's detail.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// eventLevel constants mirror db.Level*; deploy does not import db so the
// engine stays testable without a database.
const (
	LevelInfo    = "info"
	LevelSuccess = "success"
	LevelError   = "error"
)
