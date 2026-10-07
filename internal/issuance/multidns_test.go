// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/dns"
)

func bound(name string, p dns.Provider) boundProvider {
	return boundProvider{name: name, kind: "fake", provider: p}
}

func TestProviderForRoutesByZone(t *testing.T) {
	// The case the feature exists for: one certificate covering zones held
	// at different providers.
	cf := &fakeDNSProvider{Zones: []string{"example.com"}}
	ali := &fakeDNSProvider{Zones: []string{"example.net"}}
	providers := []boundProvider{bound("cloudflare", cf), bound("aliyun", ali)}

	tests := []struct{ fqdn, want string }{
		{"_acme-challenge.example.com", "cloudflare"},
		{"_acme-challenge.example.net", "aliyun"},
		{"_acme-challenge.sub.example.com", "cloudflare"},
	}
	for _, tt := range tests {
		got, err := providerFor(context.Background(), providers, tt.fqdn)
		if err != nil {
			t.Errorf("providerFor(%q) = %v", tt.fqdn, err)
			continue
		}
		if got.name != tt.want {
			t.Errorf("providerFor(%q) = %s, want %s", tt.fqdn, got.name, tt.want)
		}
	}
}

func TestProviderForSingleProviderIsNotAsked(t *testing.T) {
	// A single-provider certificate must not fail because a zone lookup was
	// briefly unavailable; if the zone is genuinely wrong, the write says
	// so with a better message than a routing error would.
	only := &fakeDNSProvider{HandleErr: errors.New("API down")}
	got, err := providerFor(context.Background(), []boundProvider{bound("only", only)},
		"_acme-challenge.example.com")
	if err != nil {
		t.Fatalf("providerFor with one provider = %v, want it used without asking", err)
	}
	if got.name != "only" {
		t.Errorf("provider = %s", got.name)
	}
}

func TestProviderForNoneClaimsTheZone(t *testing.T) {
	a := &fakeDNSProvider{Zones: []string{"example.com"}}
	b := &fakeDNSProvider{Zones: []string{"example.net"}}
	_, err := providerFor(context.Background(),
		[]boundProvider{bound("a", a), bound("b", b)}, "_acme-challenge.elsewhere.org")
	if err == nil {
		t.Fatal("a name no provider owns was routed anyway")
	}
	if !strings.Contains(err.Error(), "elsewhere.org") {
		t.Errorf("error = %v, want it to name the record", err)
	}
}

func TestProviderForAmbiguityIsRefused(t *testing.T) {
	// Two accounts claiming a zone means one is not the one meant. Picking
	// by order would write the challenge into an account nobody is
	// watching, and the CA would simply never see it.
	a := &fakeDNSProvider{Zones: []string{"example.com"}}
	b := &fakeDNSProvider{Zones: []string{"example.com"}}
	_, err := providerFor(context.Background(),
		[]boundProvider{bound("first", a), bound("second", b)}, "_acme-challenge.example.com")
	if err == nil {
		t.Fatal("an ambiguous zone was resolved silently")
	}
	for _, want := range []string{"first", "second"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
}

func TestProviderForReportsWhoCouldNotAnswer(t *testing.T) {
	// "No provider owns this" and "the one that does was unreachable" need
	// different fixes, so the second is not hidden behind the first.
	reachable := &fakeDNSProvider{Zones: []string{"example.net"}}
	broken := &fakeDNSProvider{HandleErr: errors.New("connection refused")}
	_, err := providerFor(context.Background(),
		[]boundProvider{bound("reachable", reachable), bound("broken", broken)},
		"_acme-challenge.example.com")
	if err == nil {
		t.Fatal("expected a routing failure")
	}
	if !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %v, want the unanswerable provider named", err)
	}
}

func TestProviderForPrefersTheOneThatAnswers(t *testing.T) {
	// One provider being unreachable must not block a certificate whose
	// zone is clearly owned by another.
	broken := &fakeDNSProvider{HandleErr: errors.New("API down")}
	owner := &fakeDNSProvider{Zones: []string{"example.com"}}
	got, err := providerFor(context.Background(),
		[]boundProvider{bound("broken", broken), bound("owner", owner)},
		"_acme-challenge.example.com")
	if err != nil {
		t.Fatalf("providerFor = %v, want the reachable owner used", err)
	}
	if got.name != "owner" {
		t.Errorf("provider = %s, want owner", got.name)
	}
}

func TestIssueAcrossTwoProviders(t *testing.T) {
	// End to end: a certificate covering two zones, each written through
	// the provider that owns it, and Pebble validating both.
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	is.DoH = func() DoHSettings { return DoHSettings{Skip: true} }

	// Two fakes sharing the CA's DNS server so Pebble sees both records,
	// but each claiming only its own zone.
	comProvider := &fakeDNSProvider{srv: caSrv.DNS.srv, Zones: []string{"example.com"}}
	netProvider := &fakeDNSProvider{srv: caSrv.DNS.srv, Zones: []string{"example.net"}}
	byID := map[int64]*fakeDNSProvider{}

	certID := seedIssuable(t, is, caSrv, "example.com", []string{"example.net"})

	store := is.Store.(*db.SQLite)
	comID, err := store.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "cf-com", Kind: "cloudflare", Config: `{"api_token":"t","zone_id":"z"}`})
	if err != nil {
		t.Fatal(err)
	}
	netID, err := store.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "ali-net", Kind: "aliyun",
		Config: `{"access_key_id":"k","access_key_secret":"s","domain":"example.net"}`})
	if err != nil {
		t.Fatal(err)
	}
	byID[comID], byID[netID] = comProvider, netProvider

	if err := store.SetCertificateDNSProviders(ctx, certID, []int64{comID, netID}); err != nil {
		t.Fatal(err)
	}
	// Hand back the fake matching each stored row.
	is.NewProvider = func(kind, configJSON string) (dns.Provider, error) {
		if strings.Contains(configJSON, "example.net") {
			return netProvider, nil
		}
		return comProvider, nil
	}

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue across two providers = %v", err)
	}

	// Each record must have gone to its own zone's provider.
	comWrote := strings.Join(comProvider.Added(), " ")
	netWrote := strings.Join(netProvider.Added(), " ")
	if !strings.Contains(comWrote, "example.com") {
		t.Errorf("the .com provider wrote %v", comProvider.Added())
	}
	if strings.Contains(comWrote, "example.net") {
		t.Error("the .com provider was handed the .net record")
	}
	if !strings.Contains(netWrote, "example.net") {
		t.Errorf("the .net provider wrote %v", netProvider.Added())
	}
	if strings.Contains(netWrote, "example.com") {
		t.Error("the .net provider was handed the .com record")
	}
}
