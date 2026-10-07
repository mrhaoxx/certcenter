// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Defaults for propagation checking.
const (
	DefaultDoHServer  = "https://cloudflare-dns.com/dns-query"
	DefaultMaxRetries = 12
	DefaultInterval   = 5 * time.Second

	// dohNXDOMAIN is RCODE 3: the name does not exist yet, which during
	// propagation means "not visible", not "broken".
	dohNXDOMAIN = 3
)

// Verifier polls a DNS-over-HTTPS resolver until a challenge TXT record is
// visible. Checking propagation before telling the CA the challenge is
// ready avoids burning an ACME validation attempt on a record the
// authoritative servers have not picked up.
type Verifier struct {
	Server     string
	MaxRetries int
	Interval   time.Duration

	client *http.Client
}

func NewVerifier(server string, maxRetries int, interval time.Duration) *Verifier {
	if server == "" {
		server = DefaultDoHServer
	}
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Verifier{
		Server:     server,
		MaxRetries: maxRetries,
		Interval:   interval,
		// The Rust implementation set no timeout, so a stalled resolver
		// hung the whole issuance.
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Wait polls until the record is visible or the retries run out. A query
// error counts as a failed attempt rather than aborting: resolvers are
// flaky and an issuance should ride out a transient failure.
func (v *Verifier) Wait(ctx context.Context, name, value string) error {
	var lastErr error
	for attempt := 1; attempt <= v.MaxRetries; attempt++ {
		ok, err := v.lookup(ctx, name, value)
		if err == nil && ok {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
		}
		if attempt == v.MaxRetries {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(v.Interval):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("TXT record %q did not become visible after %d attempts (last error: %w)",
			name, v.MaxRetries, lastErr)
	}
	return fmt.Errorf("TXT record %q did not become visible after %d attempts", name, v.MaxRetries)
}

// dohResponse is the application/dns-json answer shape.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// lookup performs one DoH query, reporting whether the expected value is
// present.
func (v *Verifier) lookup(ctx context.Context, name, value string) (bool, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", "TXT")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Server+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, fmt.Errorf("DoH query failed: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}

	var answer dohResponse
	if err := json.Unmarshal(raw, &answer); err != nil {
		return false, fmt.Errorf("DoH query returned malformed JSON: %w", err)
	}
	if answer.Status == dohNXDOMAIN {
		return false, nil
	}
	for _, a := range answer.Answer {
		if normalizeTXT(a.Data) == value {
			return true, nil
		}
	}
	return false, nil
}

// normalizeTXT reassembles a TXT value as the resolver reports it. Strings
// longer than 255 bytes arrive split into several quoted segments, so the
// quotes are removed and the segments concatenated rather than merely
// trimming the outer quotes — which is why the Rust implementation could
// fail to match a long record.
func normalizeTXT(data string) string {
	if !strings.Contains(data, `"`) {
		return strings.TrimSpace(data)
	}
	var b strings.Builder
	inQuotes := false
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '\\' && i+1 < len(data):
			i++
			b.WriteByte(data[i])
		case data[i] == '"':
			inQuotes = !inQuotes
		case inQuotes:
			b.WriteByte(data[i])
		}
	}
	return b.String()
}
