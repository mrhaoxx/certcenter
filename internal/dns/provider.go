// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package dns manipulates the TXT records that satisfy ACME DNS-01
// challenges. Providers are hand-written HTTP clients rather than vendor
// SDKs: pulling in alibaba-cloud-sdk-go would add hundreds of dependency
// modules, which is exactly what choosing acmez over lego's built-in
// providers avoided.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Provider creates and removes the TXT records for a DNS-01 challenge.
//
// name is always the fully-qualified record name with no trailing dot
// (e.g. "_acme-challenge.example.com"); value is the raw, unquoted digest.
//
// AddTXT must be additive: a single certificate covering both example.com
// and *.example.com produces two authorizations whose record names are
// identical but whose digests differ, so replacing same-name records would
// destroy the sibling challenge.
type Provider interface {
	AddTXT(ctx context.Context, name, value string) error
	RemoveTXT(ctx context.Context, name, value string) error

	// CanHandle reports whether this provider manages the zone the name
	// falls in. A certificate can span zones held at different providers —
	// example.com at Cloudflare and example.net at AliDNS — and each
	// challenge has to be written where its zone actually lives.
	//
	// An error means the question could not be answered, which is not the
	// same as a definite no: treating an unreachable API as "not mine"
	// would silently route the record elsewhere or blame the wrong
	// provider.
	CanHandle(ctx context.Context, fqdn string) (bool, error)
}

// Supported provider kinds. These strings are stored in
// dns_providers.kind and chosen by the UI — they are a data contract.
const (
	KindCloudflare = "cloudflare"
	KindAliyun     = "aliyun"
)

// Kinds lists the supported provider kinds, for API validation and the
// UI's picker.
func Kinds() []string {
	return []string{KindCloudflare, KindAliyun}
}

// httpClient is shared by every provider. The timeout is mandatory: the
// Rust implementation set none, so one hung DNS API call would stall an
// issuance indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// New builds a provider from its stored kind and JSON config.
func New(kind, configJSON string) (Provider, error) {
	switch kind {
	case KindCloudflare:
		return newCloudflare(configJSON)
	case KindAliyun:
		return newAliyun(configJSON)
	default:
		return nil, fmt.Errorf("unsupported DNS provider kind: %q", kind)
	}
}

// decodeConfig unmarshals a provider config, rejecting unknown keys so a
// mistyped field fails at save time instead of silently doing nothing.
func decodeConfig(configJSON string, dst any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(configJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse provider config: %w", err)
	}
	return nil
}

// requireFields reports every named field whose value is empty, so a
// half-filled form is fixed in one round rather than one field at a time.
func requireFields(fields map[string]string) error {
	var missing []string
	for name, value := range fields {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("provider config is missing required fields: %v", missing)
}
