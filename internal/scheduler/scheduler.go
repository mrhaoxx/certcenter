// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package scheduler renews certificates before they expire.
package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// Interval is how often the scheduler looks for work.
//
// The Rust implementation used a cron fixed at 02:00 UTC, so a process that
// happened to restart at 01:59 skipped that day entirely. Expiry is measured
// in days, so an hourly sweep is ample and survives restarts.
const Interval = time.Hour

// MaxConcurrent bounds parallel renewals. The Rust loop was fully
// sequential, so one certificate stuck against an unresponsive DNS API
// stalled the entire batch.
const MaxConcurrent = 3

// Issuer is the part of issuance.Issuer the scheduler needs.
type Issuer interface {
	Issue(ctx context.Context, certID int64, trigger string) error
}

// Deployer installs a renewed certificate.
type Deployer interface {
	DeployCertificate(ctx context.Context, certID int64, trigger string) error
}

// Scheduler renews certificates whose time has come.
type Scheduler struct {
	Store    db.Store
	Issuer   Issuer
	Deployer Deployer

	// Now is overridable in tests.
	Now func() time.Time
	// OnChange is called after a sweep changes something, so the UI's
	// event stream can be nudged.
	OnChange func()
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run sweeps until the context is cancelled. It sweeps once immediately so
// a restart picks up anything that came due while the process was down.
func (s *Scheduler) Run(ctx context.Context) {
	slog.Info("renewal scheduler started", "interval", Interval)
	if err := s.Sweep(ctx); err != nil {
		slog.Warn("renewal sweep failed", "err", err)
	}

	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("renewal scheduler stopped")
			return
		case <-ticker.C:
			if err := s.Sweep(ctx); err != nil {
				slog.Warn("renewal sweep failed", "err", err)
			}
		}
	}
}

// Sweep renews every certificate currently due.
func (s *Scheduler) Sweep(ctx context.Context) error {
	due, err := s.Store.DueForRenewal(ctx, s.now())
	if err != nil {
		return err
	}
	if len(due) == 0 {
		return nil
	}
	slog.Info("renewing certificates", "count", len(due))

	sem := make(chan struct{}, MaxConcurrent)
	var wg sync.WaitGroup
	for _, cert := range due {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(cert db.Certificate) {
			defer wg.Done()
			defer func() { <-sem }()
			s.renew(ctx, cert)
		}(cert)
	}
	wg.Wait()

	if s.OnChange != nil {
		s.OnChange()
	}
	return nil
}

func (s *Scheduler) renew(ctx context.Context, cert db.Certificate) {
	err := s.Issuer.Issue(ctx, cert.ID, "auto")
	if err != nil {
		slog.Warn("automatic renewal failed", "certificate", cert.ID, "domain", cert.Domain, "err", err)
		// Backoff, so the next sweep retries later rather than immediately —
		// and, crucially, retries at all: the Rust scheduler left a failed
		// certificate in a state its own query could never select again.
		if berr := s.Store.RecordRenewalFailure(ctx, cert.ID, s.now()); berr != nil {
			slog.Warn("could not record the renewal failure", "certificate", cert.ID, "err", berr)
		}
		detail := err.Error()
		certID := cert.ID
		_ = s.Store.AppendLog(ctx, db.OperationLog{
			Action: "renew_failed", ResourceType: "certificate",
			ResourceID: &certID, Detail: &detail, Operator: "system",
		})
		return
	}

	certID := cert.ID
	_ = s.Store.AppendLog(ctx, db.OperationLog{
		Action: "renewed", ResourceType: "certificate",
		ResourceID: &certID, Operator: "system",
	})

	if s.Deployer == nil {
		return
	}
	// A renewed certificate nobody installed is not renewed in any way that
	// matters.
	if err := s.Deployer.DeployCertificate(ctx, cert.ID, "auto"); err != nil {
		slog.Warn("post-renewal deployment failed", "certificate", cert.ID, "err", err)
	}
}
