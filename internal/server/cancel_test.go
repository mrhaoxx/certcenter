// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"sync"
	"testing"
)

func TestCancelStopsARunningOperation(t *testing.T) {
	// Issuance takes minutes — a slow provider, a propagation wait, a CA
	// not answering — and the only way out used to be restarting the
	// process, which left the run orphaned.
	srv := newTestServer(t)
	srv.Running = NewRunning()

	ctx, cancel := context.WithCancel(context.Background())
	done := srv.Running.add(1, cancel)
	defer done()

	rec := authed(t, srv, http.MethodPost, "/api/certificates/1/cancel", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body)
	}
	select {
	case <-ctx.Done():
	default:
		t.Error("the operation's context was not cancelled")
	}
}

func TestCancelWhenNothingIsRunning(t *testing.T) {
	// The work may have finished between the page rendering and the click,
	// which is ordinary rather than an error worth a 500.
	srv := newTestServer(t)
	srv.Running = NewRunning()

	rec := authed(t, srv, http.MethodPost, "/api/certificates/99/cancel", "")
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestCancelRequiresSession(t *testing.T) {
	srv := newTestServer(t)
	srv.Running = NewRunning()
	rec := postJSON(t, srv, "/api/certificates/1/cancel", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRunningRegistryIsConcurrencySafe(t *testing.T) {
	// The registry is written by issuance goroutines and read by request
	// handlers at the same time.
	r := NewRunning()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			_, cancel := context.WithCancel(context.Background())
			done := r.add(id, cancel)
			r.active()
			r.cancel(id)
			done()
		}(int64(i))
	}
	wg.Wait()
	if got := len(r.active()); got != 0 {
		t.Errorf("%d entries left registered, want 0", got)
	}
}

func TestDeregisterRemovesTheEntry(t *testing.T) {
	// A finished run must not leave a cancel behind: cancelling it later
	// would report success while doing nothing.
	r := NewRunning()
	_, cancel := context.WithCancel(context.Background())
	done := r.add(7, cancel)
	done()

	if r.cancel(7) {
		t.Error("cancel reported success for a finished operation")
	}
}

func TestCancelledDistinguishesDeliberateStops(t *testing.T) {
	// A cancellation must not feed the retry backoff or land in the list
	// operators scan for faults.
	if !cancelled(context.Canceled) {
		t.Error("context.Canceled was not recognised")
	}
	if cancelled(context.DeadlineExceeded) {
		t.Error("a timeout was mistaken for a deliberate cancellation")
	}
	if cancelled(nil) {
		t.Error("nil was treated as a cancellation")
	}
}
