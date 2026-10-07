// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"fmt"
	"strings"

	"github.com/mrhaoxx/certcenter/internal/dns"
)

// boundProvider is a configured provider plus enough identity to explain
// itself in the timeline.
type boundProvider struct {
	id       int64
	name     string
	kind     string
	provider dns.Provider
}

// loadProviders builds every DNS provider a certificate may use.
//
// The set comes from certificate_dns_providers; the single column it
// replaced is the fallback for a store that predates the table.
func (is *Issuer) loadProviders(ctx context.Context, certID, fallbackID int64) ([]boundProvider, error) {
	rows, err := is.Store.ListCertificateDNSProviders(ctx, certID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		kind, configJSON, err := is.dnsProviderRow(ctx, fallbackID)
		if err != nil {
			return nil, err
		}
		p, err := is.newProvider(kind, configJSON)
		if err != nil {
			return nil, err
		}
		return []boundProvider{{id: fallbackID, name: kind, kind: kind, provider: p}}, nil
	}

	out := make([]boundProvider, 0, len(rows))
	for _, row := range rows {
		p, err := is.newProvider(row.Kind, row.Config)
		if err != nil {
			return nil, fmt.Errorf("build DNS provider %q: %w", row.Name, err)
		}
		out = append(out, boundProvider{id: row.ID, name: row.Name, kind: row.Kind, provider: p})
	}
	return out, nil
}

// providerFor picks the provider that owns the zone a record belongs in.
//
// With one provider the question is not asked: a single-provider
// certificate should not fail because a zone lookup was momentarily
// unavailable, and if the zone really is wrong the write itself says so
// with a better message.
//
// Ambiguity is refused rather than resolved by order. Two accounts both
// claiming a zone means one of them is not the one the operator meant, and
// picking silently would write the challenge somewhere they are not
// looking.
func providerFor(ctx context.Context, providers []boundProvider, fqdn string) (boundProvider, error) {
	if len(providers) == 1 {
		return providers[0], nil
	}

	var (
		matched    []boundProvider
		unanswered []string
	)
	for _, p := range providers {
		ok, err := p.provider.CanHandle(ctx, fqdn)
		if err != nil {
			// Not fatal on its own: another provider may answer clearly.
			// It is reported if nothing does, because "no provider owns
			// this" and "the one that does could not be reached" call for
			// different fixes.
			unanswered = append(unanswered, fmt.Sprintf("%s: %v", p.name, err))
			continue
		}
		if ok {
			matched = append(matched, p)
		}
	}

	switch len(matched) {
	case 1:
		return matched[0], nil
	case 0:
		msg := fmt.Sprintf("no configured DNS provider manages the zone for %q", fqdn)
		if len(unanswered) > 0 {
			msg += "; some could not be asked: " + strings.Join(unanswered, "; ")
		}
		return boundProvider{}, fmt.Errorf("%s", msg)
	default:
		names := make([]string, 0, len(matched))
		for _, p := range matched {
			names = append(names, p.name)
		}
		return boundProvider{}, fmt.Errorf(
			"%d DNS providers claim the zone for %q (%s); remove one from this certificate",
			len(matched), fqdn, strings.Join(names, ", "))
	}
}
