// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/dns"
)

// TestIssueThroughDelegatedZone is the case the whole feature exists for:
// the operator has no DNS credentials for the certificate's own domain, so
// its challenge name is CNAMEd to a zone they do control. The TXT goes in
// the delegated zone and Pebble follows the CNAME exactly as a real CA
// would.
func TestIssueThroughDelegatedZone(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	const (
		domain    = "delegated.example.com"
		challenge = "_acme-challenge.delegated.example.com"
		target    = "_acme-challenge.validation.example.net"
	)
	caSrv.DNS.srv.AddDNSCNAMERecord(challenge, target)
	t.Cleanup(func() { caSrv.DNS.srv.DeleteDNSCNAMERecord(challenge) })

	// The resolver the issuer consults for delegation is the same fake DNS
	// server Pebble validates against, so both see the CNAME.
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true} }
	is.ResolveTarget = func(ctx context.Context, name string) (string, error) {
		if strings.EqualFold(name, challenge) {
			return target, nil
		}
		return name, nil
	}

	certID := seedIssuable(t, is, caSrv, domain, nil)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() through a delegated zone = %v", err)
	}

	// Check what was written during the run: a successful issuance removes
	// its records afterwards, so the live values are empty by now.
	added := caSrv.DNS.Added()
	var wroteTarget, wroteOriginal bool
	for _, n := range added {
		switch {
		case strings.EqualFold(n, target):
			wroteTarget = true
		case strings.EqualFold(n, challenge):
			wroteOriginal = true
		}
	}
	if !wroteTarget {
		t.Errorf("no TXT was written to the delegated name %q; wrote %v", target, added)
	}
	if wroteOriginal {
		t.Errorf("a TXT was written to the original name %q; the delegation was ignored", challenge)
	}
}

// TestDelegationLookupFailureDoesNotBlockIssuance keeps a resolver outage
// from breaking certificates that use no delegation at all.
func TestDelegationLookupFailureDoesNotBlockIssuance(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	// A resolver that is down for the delegation lookup.
	is.DoH = func() DoHSettings {
		return DoHSettings{Skip: true, Server: "https://127.0.0.1:1/dns-query",
			Retries: 1, Interval: time.Millisecond}
	}
	is.ResolveTarget = dns.NewVerifier("https://127.0.0.1:1/dns-query", 1, time.Millisecond).ResolveChallengeTarget

	certID := seedIssuable(t, is, caSrv, "plain.example.com", nil)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v; a delegation lookup failure must not stop an unaliased issuance", err)
	}
}
