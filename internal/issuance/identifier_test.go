// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"strings"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestIdentifierType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com", "dns"},
		{"*.example.com", "dns"},
		{"192.0.2.1", "ip"},
		{"2001:db8::1", "ip"},
		{"192.0.2.1.example.com", "dns"},
	}
	for _, tt := range tests {
		if got := IdentifierType(tt.in); got != tt.want {
			t.Errorf("IdentifierType(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIPAddressIsRefusedWithAnExplanation(t *testing.T) {
	// RFC 8738 forbids dns-01 for IP identifiers, and this service does
	// DNS-01 only. Failing at order creation with the reason beats letting
	// the CA accept the order and failing later on a missing challenge.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()

	certID := seedIssuable(t, is, caSrv, "192.0.2.10", nil)
	err := is.Issue(ctx, certID, "manual")
	if err == nil {
		t.Fatal("Issue() for an IP address = nil, want a refusal")
	}
	for _, want := range []string{"IP address", "http-01"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to mention %q", err, want)
		}
	}

	// And the refusal is on the timeline, not only in the return value.
	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	events, err := is.Store.ListRunEvents(ctx, runs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	var explained bool
	for _, e := range events {
		if e.Level == db.LevelError && strings.Contains(e.Message, "IP addresses") {
			explained = true
		}
	}
	if !explained {
		t.Error("the timeline does not explain why the issuance was refused")
	}
}

func TestSplitIdentifiers(t *testing.T) {
	names, ips := SplitIdentifiers([]string{"a.example.com", "192.0.2.1", "b.example.com", "2001:db8::1"})
	if len(names) != 2 || names[0] != "a.example.com" {
		t.Errorf("names = %v", names)
	}
	if len(ips) != 2 {
		t.Errorf("ips = %v", ips)
	}
}
