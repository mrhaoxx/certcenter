// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// cnameServer answers CNAME queries from a map, and NXDOMAIN otherwise.
func cnameServer(t *testing.T, chain map[string]string) *Verifier {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		target, ok := chain[name]
		if !ok {
			w.Write([]byte(`{"Status":3}`))
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"type":5,"data":"` + target + `."}]}`))
	}))
	t.Cleanup(srv.Close)
	return NewVerifier(srv.URL, 1, time.Millisecond)
}

func TestResolveChallengeTargetFollowsDelegation(t *testing.T) {
	// The whole point: the operator cannot write to example.com, so they
	// point its challenge name at a zone they do control. Nothing about
	// this is configured here — it is discovered.
	v := cnameServer(t, map[string]string{
		"_acme-challenge.example.com": "_acme-challenge.delegated.net",
	})
	got, err := v.ResolveChallengeTarget(context.Background(), "_acme-challenge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "_acme-challenge.delegated.net" {
		t.Errorf("target = %q, want the delegated name", got)
	}
}

func TestResolveChallengeTargetFollowsMultipleHops(t *testing.T) {
	v := cnameServer(t, map[string]string{
		"_acme-challenge.example.com": "step1.delegated.net",
		"step1.delegated.net":         "step2.other.net",
	})
	got, err := v.ResolveChallengeTarget(context.Background(), "_acme-challenge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got != "step2.other.net" {
		t.Errorf("target = %q, want the end of the chain", got)
	}
}

func TestResolveChallengeTargetWithoutDelegation(t *testing.T) {
	v := cnameServer(t, nil)
	const name = "_acme-challenge.example.com"
	got, err := v.ResolveChallengeTarget(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if got != name {
		t.Errorf("target = %q, want the name unchanged when nothing is delegated", got)
	}
}

func TestResolveChallengeTargetStopsOnALoop(t *testing.T) {
	// A loop would otherwise hang the issuance for as long as the resolver
	// keeps answering.
	v := cnameServer(t, map[string]string{
		"a.example.com": "b.example.com",
		"b.example.com": "a.example.com",
	})
	if _, err := v.ResolveChallengeTarget(context.Background(), "a.example.com"); err == nil {
		t.Error("a CNAME loop was followed without complaint")
	}
}

func TestResolveChallengeTargetSurvivesAResolverOutage(t *testing.T) {
	// A resolver that is down must not break an issuance that needs no
	// delegation at all, so the original name comes back with the error
	// for the caller to weigh.
	v := NewVerifier("https://127.0.0.1:1/dns-query", 1, time.Millisecond)
	const name = "_acme-challenge.example.com"
	got, err := v.ResolveChallengeTarget(context.Background(), name)
	if err == nil {
		t.Error("expected the lookup failure to be reported")
	}
	if got != name {
		t.Errorf("target = %q, want the original name as the fallback", got)
	}
}
