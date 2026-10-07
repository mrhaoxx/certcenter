// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"log/slog"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// recorder writes one run's timeline. Every issuance phase calls it, which
// is the whole reason this project drives the ACME state machine itself:
// the high-level API would collapse the timeline into a single call, and
// lego's process-global logger cannot attribute lines to a certificate at
// all when issuances run concurrently.
type recorder struct {
	store db.Store
	runID int64
	// onEvent nudges the UI's event stream after each entry. An issuance
	// runs for minutes; without this the timeline only appears once the
	// whole thing is over, which is the one moment it stops being useful.
	onEvent func()
}

// event appends a timeline entry. Failing to record must not abort an
// otherwise healthy issuance, so the error is logged and swallowed.
func (r *recorder) event(ctx context.Context, eventType, message, detail, level string) {
	e := db.Event{Type: eventType, Message: message, Level: level}
	if detail != "" {
		e.Detail = &detail
	}
	if err := r.store.AppendEvent(ctx, r.runID, e); err != nil {
		slog.Warn("could not record issuance event",
			"run", r.runID, "type", eventType, "err", err)
		return
	}
	if r.onEvent != nil {
		r.onEvent()
	}
}

func (r *recorder) info(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelInfo)
}

func (r *recorder) success(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelSuccess)
}

func (r *recorder) failure(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelError)
}
