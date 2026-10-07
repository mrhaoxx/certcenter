// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// running tracks work that can be stopped.
//
// Issuance takes minutes — a slow DNS provider, a propagation wait, a CA
// that is not answering — and until now the only way out was to wait or
// restart the process. Restarting was worse than waiting: it left the run
// orphaned.
type running struct {
	mu sync.Mutex
	// byCertificate holds one cancel per certificate. A certificate cannot
	// have two issuances at once, so the key needs no more structure.
	byCertificate map[int64]context.CancelFunc
}

// NewRunning builds the registry of cancellable work.
func NewRunning() *running {
	return &running{byCertificate: map[int64]context.CancelFunc{}}
}

// add registers a cancellable operation and returns the function to
// deregister it.
func (r *running) add(certID int64, cancel context.CancelFunc) func() {
	r.mu.Lock()
	r.byCertificate[certID] = cancel
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.byCertificate, certID)
		r.mu.Unlock()
	}
}

// cancel stops the operation for a certificate, reporting whether one was
// running.
func (r *running) cancel(certID int64) bool {
	r.mu.Lock()
	cancel, ok := r.byCertificate[certID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	cancel()
	return true
}

// active reports the certificate ids currently working, so the UI can show
// a cancel affordance only where it would do something.
func (r *running) active() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int64, 0, len(r.byCertificate))
	for id := range r.byCertificate {
		out = append(out, id)
	}
	return out
}

func (s *Server) registerCancelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/certificates/{id}/cancel", s.requireSession(s.handleCancel))
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	if s.Running == nil || !s.Running.cancel(id) {
		// Not an error worth a 500: the work may have finished between the
		// page rendering and the click.
		s.writeErr(w, http.StatusConflict, "NOT_RUNNING",
			"nothing is running for this certificate", nil)
		return
	}
	s.audit(r, "cancel", "certificate", id, "Cancelled the running operation")
	s.Events.Publish(TopicCertificates)
	s.Events.Publish(TopicRuns)
	w.WriteHeader(http.StatusNoContent)
}

// cancelled reports whether an error marks a deliberate stop rather than a
// fault, so the two are not filed the same way — a cancellation must not
// feed the retry backoff.
func cancelled(err error) bool {
	return errors.Is(err, context.Canceled)
}
