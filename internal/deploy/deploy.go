// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// DeployTimeout bounds one target's deployment. A stuck SSH host must not
// hold up the other targets.
const DeployTimeout = 5 * time.Minute

// Deployer runs a certificate's bindings and records each attempt.
type Deployer struct {
	Store db.Store
	// ManagementURL is injected into configcenter targets from the app's
	// [bus] config.
	ManagementURL func() string
	// NewTarget is overridable so tests can inject fakes.
	NewTarget func(kind, configJSON string, opts Options) (Target, error)
}

func (d *Deployer) newTarget(kind, configJSON string) (Target, error) {
	opts := Options{}
	if d.ManagementURL != nil {
		opts.ManagementURL = d.ManagementURL()
	}
	if d.NewTarget != nil {
		return d.NewTarget(kind, configJSON, opts)
	}
	return New(kind, configJSON, opts)
}

// DeployCertificate installs an issued certificate on every bound target.
//
// Targets run in sequence and one failure does not stop the rest: a broken
// CDN credential should not keep the web servers on an expiring
// certificate. The returned error reports how many targets failed.
func (d *Deployer) DeployCertificate(ctx context.Context, certID int64, trigger string) error {
	cert, err := d.Store.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}
	if cert.Status != "issued" {
		return fmt.Errorf("certificate %d is %s, not issued", certID, cert.Status)
	}
	if cert.CertPEM == nil || cert.KeyPEM == "" {
		return fmt.Errorf("certificate %d has no material to deploy", certID)
	}

	data := &CertificateData{
		Domain:  cert.Domain,
		CertPEM: *cert.CertPEM,
		KeyPEM:  cert.KeyPEM,
	}
	if cert.ChainPEM != nil {
		data.ChainPEM = *cert.ChainPEM
	}

	deployments, err := d.Store.ListDeployments(ctx, certID)
	if err != nil {
		return err
	}

	var failed int
	for _, dep := range deployments {
		if err := d.deployOne(ctx, dep, data, trigger); err != nil {
			failed++
			slog.Warn("deployment failed",
				"certificate", certID, "target", dep.TargetName, "err", err)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d deployments failed", failed, len(deployments))
	}
	return nil
}

// deployOne runs a single binding, opening a run so the timeline shows the
// attempt whether it succeeds or not.
func (d *Deployer) deployOne(ctx context.Context, dep db.Deployment,
	data *CertificateData, trigger string) error {

	ctx, cancel := context.WithTimeout(ctx, DeployTimeout)
	defer cancel()

	run, err := d.Store.StartRun(ctx, db.RunKindDeploy, dep.CertificateID, &dep.ID, trigger)
	if err != nil {
		return fmt.Errorf("start deploy run: %w", err)
	}

	record := func(e Event) {
		level := e.Level
		if level == "" {
			level = db.LevelInfo
		}
		ev := db.Event{Type: e.Type, Message: e.Message, Level: level}
		if e.Detail != "" {
			detail := e.Detail
			ev.Detail = &detail
		}
		if err := d.Store.AppendEvent(ctx, run.ID, ev); err != nil {
			slog.Warn("could not record deployment event", "run", run.ID, "err", err)
		}
	}

	record(Event{Type: "start", Level: db.LevelInfo,
		Message: fmt.Sprintf("Deploying to %q (%s)", dep.TargetName, dep.TargetKind)})

	target, err := d.buildTarget(ctx, dep)
	if err != nil {
		record(Event{Type: "error", Level: db.LevelError,
			Message: "Could not build the deploy target", Detail: err.Error()})
		_ = d.Store.FinishRun(ctx, run.ID, db.RunStatusError, err.Error())
		_ = d.Store.UpdateDeploymentResult(ctx, dep.ID, "failed", err.Error())
		return err
	}

	// Events come back alongside the error, so a failed deployment's
	// timeline — the part an operator actually needs — is still persisted.
	events, deployErr := target.Deploy(ctx, data)
	for _, e := range events {
		record(e)
	}

	if deployErr != nil {
		record(Event{Type: "failed", Level: db.LevelError,
			Message: fmt.Sprintf("Deployment failed: %v", deployErr)})
		_ = d.Store.FinishRun(ctx, run.ID, db.RunStatusError, deployErr.Error())
		_ = d.Store.UpdateDeploymentResult(ctx, dep.ID, "failed", deployErr.Error())
		return deployErr
	}

	_ = d.Store.FinishRun(ctx, run.ID, db.RunStatusSuccess, "")
	return d.Store.UpdateDeploymentResult(ctx, dep.ID, "success", "")
}

func (d *Deployer) buildTarget(ctx context.Context, dep db.Deployment) (Target, error) {
	stored, err := d.Store.GetDeployTarget(ctx, dep.DeployTargetID)
	if err != nil {
		return nil, err
	}
	return d.newTarget(stored.Kind, stored.Config)
}
