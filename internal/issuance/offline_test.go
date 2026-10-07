// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"testing"
)

// TestIssuanceMakesNoOutboundLookupWithoutAResolver pins that a run with
// no DoH server configured asks nobody.
//
// NewVerifier substitutes a public resolver for an empty address, so
// adding the CNAME delegation lookup quietly turned every issuance into an
// outbound query — including in this suite, which runs against an
// in-process CA precisely so it needs no network. It showed up as tests
// that took ten seconds each and hung when the network was unhappy.
func TestIssuanceMakesNoOutboundLookupWithoutAResolver(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	// Skip:true with no Server is exactly what the test issuer uses, and
	// what an operator gets before configuring anything.
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true} }
	is.ResolveTarget = nil

	certID := seedIssuable(t, is, caSrv, "offline.example.com", nil)
	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	// The record has to land under its own name: with no resolver there is
	// no delegation to discover, and the name must not be mangled.
	var wroteChallenge bool
	for _, n := range caSrv.DNS.Added() {
		if n == "_acme-challenge.offline.example.com" {
			wroteChallenge = true
		}
	}
	if !wroteChallenge {
		t.Errorf("wrote %v, want the unresolved challenge name", caSrv.DNS.Added())
	}
}
