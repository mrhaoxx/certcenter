// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package secret keeps stored credentials from leaving the process.
//
// It lives apart from the HTTP layer because the bus exposes the same
// resources over a different transport: putting the masking in one
// handler package would have left the other returning tokens verbatim,
// which is exactly what happened.
package secret

import (
	"encoding/json"
	"strings"
)

// Value replaces a secret on its way out. It is deliberately
// recognisable: the UI shows it, and an unchanged field comes back wearing
// it, which is how restore() knows to keep what is already stored.
const Value = "••••••••"

// secretKeys are config fields that must never leave the server. A DNS
// provider's config holds an API token; a deploy target's holds SSH
// private keys, passphrases and webhook credentials. Both were being
// returned verbatim to anyone with a session, in every list response.
//
// Matching is by key name and applied recursively, because an SSH target
// keeps its private key inside a pipeline step rather than at the top
// level, and a per-kind field list would have missed it.
var secretKeys = map[string]bool{
	"api_token":         true,
	"access_key_secret": true,
	"secret_access_key": true,
	"secret_key":        true,
	"secret_id":         true,
	"private_key":       true,
	"password":          true,
	"passphrase":        true,
	"token":             true,
}

// secretContainers hold arbitrary keys whose values are all suspect —
// webhook headers routinely carry an Authorization value.
var secretContainers = map[string]bool{
	"headers": true,
}

func isSecretKey(k string) bool {
	return secretKeys[strings.ToLower(k)]
}

// RedactConfig masks every secret in a JSON config document. A document
// that will not parse is replaced wholesale rather than passed through:
// the safe failure is to reveal nothing.
func Redact(configJSON string) string {
	var v any
	if err := json.Unmarshal([]byte(configJSON), &v); err != nil {
		return "{}"
	}
	out, err := json.Marshal(redactValue(v, false))
	if err != nil {
		return "{}"
	}
	return string(out)
}

// redactValue walks the document. inContainer marks that every value here
// belongs to something like a header map and is therefore suspect.
func redactValue(v any, inContainer bool) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			switch {
			case isSecretKey(k) || inContainer:
				if s, ok := child.(string); ok && s != "" {
					out[k] = Value
					continue
				}
				out[k] = child
			case secretContainers[strings.ToLower(k)]:
				out[k] = redactValue(child, true)
			default:
				out[k] = redactValue(child, false)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = redactValue(child, inContainer)
		}
		return out
	default:
		return v
	}
}

// RestoreConfig puts stored secrets back wherever the incoming document
// still carries the mask, so editing a name does not blank a credential
// the form never showed.
func Restore(incoming, stored string) string {
	var in any
	if err := json.Unmarshal([]byte(incoming), &in); err != nil {
		return incoming // let the provider's own parser reject it
	}
	var old any
	if err := json.Unmarshal([]byte(stored), &old); err != nil {
		return incoming
	}
	out, err := json.Marshal(restoreValue(in, old))
	if err != nil {
		return incoming
	}
	return string(out)
}

func restoreValue(incoming, stored any) any {
	inMap, ok := incoming.(map[string]any)
	if !ok {
		return incoming
	}
	oldMap, _ := stored.(map[string]any)

	out := make(map[string]any, len(inMap))
	for k, child := range inMap {
		var prior any
		if oldMap != nil {
			prior = oldMap[k]
		}
		if s, isStr := child.(string); isStr && s == Value {
			// Only a previously stored string can be restored; anything
			// else leaves the mask to fail validation loudly.
			if ps, ok := prior.(string); ok {
				out[k] = ps
				continue
			}
		}
		switch child.(type) {
		case map[string]any:
			out[k] = restoreValue(child, prior)
		case []any:
			out[k] = restoreSlice(child.([]any), prior)
		default:
			out[k] = child
		}
	}
	return out
}

func restoreSlice(incoming []any, stored any) []any {
	oldSlice, _ := stored.([]any)
	out := make([]any, len(incoming))
	for i, child := range incoming {
		var prior any
		if i < len(oldSlice) {
			prior = oldSlice[i]
		}
		switch child.(type) {
		case map[string]any:
			out[i] = restoreValue(child, prior)
		case []any:
			out[i] = restoreSlice(child.([]any), prior)
		default:
			out[i] = child
		}
	}
	return out
}
