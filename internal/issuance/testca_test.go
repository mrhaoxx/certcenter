// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/letsencrypt/challtestsrv"
	"github.com/letsencrypt/pebble/v2/ca"
	pebbledb "github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// testCA is an in-process ACME CA: Pebble for the protocol, challtestsrv as
// the DNS server Pebble's validator resolves TXT records against. No
// network, no Docker — a full DNS-01 issuance runs in well under a second.
type testCA struct {
	DirectoryURL string
	HTTPClient   *http.Client
	DNS          *fakeDNSProvider
}

// EAB credentials the EAB-requiring test CA accepts. The MAC key is
// base64url, as CAs issue it.
const (
	testEABKeyID  = "kid-1"
	testEABMACKey = "zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MtBUyZk9AmKq5"
)

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	return newTestCAWith(t, testCAOptions{})
}

// newProfileTestCA offers profiles with genuinely different lifetimes, so a
// test can prove the requested profile changes what the CA issues.
//
// It is a separate constructor because Pebble picks a *random* profile for
// an order that names none — "in true pebble chaos fashion", per its own
// source. Handing that CA to every test would make any assertion about a
// certificate's lifetime flaky.
func newProfileTestCA(t *testing.T) *testCA {
	t.Helper()
	return newTestCAWith(t, testCAOptions{profiles: map[string]ca.Profile{
		"classic":    {Description: "90 days", ValidityPeriod: 90 * 24 * 3600},
		"shortlived": {Description: "6 days", ValidityPeriod: 6 * 24 * 3600},
	}})
}

// newEABTestCA returns a CA that rejects newAccount without an external
// account binding, the way ZeroSSL and Google Trust Services do.
func newEABTestCA(t *testing.T) *testCA {
	t.Helper()
	return newTestCAWith(t, testCAOptions{requireEAB: true})
}

type testCAOptions struct {
	requireEAB bool
	// profiles overrides the single deterministic profile. Leave nil unless
	// the test is specifically about profiles.
	profiles map[string]ca.Profile
}

func newTestCAWith(t *testing.T, opts testCAOptions) *testCA {
	t.Helper()
	// Pebble sleeps a random interval before validating unless told not to.
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	challSrv, err := challtestsrv.New(challtestsrv.Config{
		DNSAddrs: []string{dnsAddr},
		Log:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("challtestsrv.New: %v", err)
	}
	go challSrv.Run()
	t.Cleanup(challSrv.Shutdown)

	logger := log.New(io.Discard, "pebble ", 0)
	memDB := pebbledb.NewMemoryStore()
	// One profile by default: Pebble picks a random profile when an order
	// names none, so a single entry keeps every other test's lifetime
	// assertions deterministic. ValidityPeriod is in seconds; 0 means
	// Pebble's own 90-day default.
	profiles := opts.profiles
	if profiles == nil {
		profiles = map[string]ca.Profile{"default": {Description: "default", ValidityPeriod: 0}}
	}
	pebbleCA := ca.New(logger, memDB, "", "ecdsa", 0, 1, profiles)
	// httpPort/tlsPort go unused for DNS-01; dnsAddr is what makes the
	// validator resolve our TXT records instead of the public internet's.
	pebbleVA := va.New(logger, 0, 0, true, dnsAddr, memDB)
	if opts.requireEAB {
		if err := memDB.AddExternalAccountKeyByID(testEABKeyID, testEABMACKey); err != nil {
			t.Fatalf("seeding the EAB key: %v", err)
		}
	}
	wfeImpl := wfe.New(logger, memDB, pebbleVA, pebbleCA, nil, true, opts.requireEAB, 0, 0)

	srv := httptest.NewUnstartedServer(wfeImpl.Handler())
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &testCA{
		DirectoryURL: srv.URL + wfe.DirectoryPath,
		HTTPClient:   srv.Client(),
		DNS:          &fakeDNSProvider{srv: challSrv},
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// fakeDNSProvider implements dns.Provider on top of challtestsrv.
//
// It keeps its own name→values map instead of delegating removal straight to
// challtestsrv, whose DeleteDNSTXTRecord drops every value for a name.
// Mirroring the real (name, value) contract is the point: a provider that
// deletes too much is exactly the bug milestone 2a fixed, and a fake that
// also deletes too much would hide it.
type fakeDNSProvider struct {
	srv *challtestsrv.ChallSrv

	mu     sync.Mutex
	values map[string][]string
	// added keeps every name ever written, because a successful issuance
	// cleans up after itself and the current values are empty by the time
	// a test looks.
	added []string
	// Zones limits what this provider claims; empty claims everything.
	Zones []string
	// HandleErr makes CanHandle unanswerable, standing in for an API that
	// is down.
	HandleErr error

	// AddErr/RemoveErr inject provider failures.
	AddErr    error
	RemoveErr error
	// SuppressDNSSync keeps AddTXT from publishing to challtestsrv, so a
	// test can make a challenge fail validation while still exercising the
	// provider and cleanup paths.
	SuppressDNSSync bool
}

func (f *fakeDNSProvider) AddTXT(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.AddErr != nil {
		return f.AddErr
	}
	if f.values == nil {
		f.values = map[string][]string{}
	}
	f.values[name] = append(f.values[name], value)
	f.added = append(f.added, name)
	if !f.SuppressDNSSync {
		f.srv.AddDNSTXTRecord(name, value)
	}
	return nil
}

func (f *fakeDNSProvider) RemoveTXT(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.RemoveErr != nil {
		return f.RemoveErr
	}
	kept := make([]string, 0, len(f.values[name]))
	for _, v := range f.values[name] {
		if v != value {
			kept = append(kept, v)
		}
	}
	f.values[name] = kept

	// challtestsrv only offers "delete every value for this name", so
	// re-add the survivors.
	f.srv.DeleteDNSTXTRecord(name)
	for _, v := range kept {
		f.srv.AddDNSTXTRecord(name, v)
	}
	return nil
}

// CanHandle claims everything unless Zones is set, so single-provider
// tests need no setup and the routing tests can be explicit.
func (f *fakeDNSProvider) CanHandle(_ context.Context, fqdn string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.HandleErr != nil {
		return false, f.HandleErr
	}
	if len(f.Zones) == 0 {
		return true, nil
	}
	for _, z := range f.Zones {
		if fqdn == z || strings.HasSuffix(fqdn, "."+z) {
			return true, nil
		}
	}
	return false, nil
}

// Added reports every name written during the run, surviving cleanup.
func (f *fakeDNSProvider) Added() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.added))
	copy(out, f.added)
	return out
}

// Values reports the records currently present, for assertions.
func (f *fakeDNSProvider) Values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.values[name]))
	copy(out, f.values[name])
	return out
}

func TestTestCAStartsAndServesDirectory(t *testing.T) {
	caSrv := newTestCA(t)
	resp, err := caSrv.HTTPClient.Get(caSrv.DirectoryURL)
	if err != nil {
		t.Fatalf("fetching the directory: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("directory status = %d, want 200", resp.StatusCode)
	}
}

func TestFakeDNSProviderRemovesOnlyTheGivenValue(t *testing.T) {
	// 这个假 provider 自己得先正确，否则后面的断言都没意义。
	caSrv := newTestCA(t)
	ctx := context.Background()
	name := "_acme-challenge.example.com"

	if err := caSrv.DNS.AddTXT(ctx, name, "first"); err != nil {
		t.Fatal(err)
	}
	if err := caSrv.DNS.AddTXT(ctx, name, "second"); err != nil {
		t.Fatal(err)
	}
	if got := caSrv.DNS.Values(name); len(got) != 2 {
		t.Fatalf("values = %v, want both present", got)
	}
	if err := caSrv.DNS.RemoveTXT(ctx, name, "first"); err != nil {
		t.Fatal(err)
	}
	got := caSrv.DNS.Values(name)
	if len(got) != 1 || got[0] != "second" {
		t.Errorf("values = %v, want only [second]", got)
	}
	if live := caSrv.DNS.srv.GetDNSTXTRecords(name); len(live) != 1 || live[0] != "second" {
		t.Errorf("challtestsrv records = %v, want only [second]", live)
	}
}
