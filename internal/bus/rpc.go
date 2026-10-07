// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package bus

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/secret"
)

// The method names below are an external contract: ServerAgent calls them
// by these exact strings, so they keep the Rust implementation's names even
// where the API was otherwise redesigned.
//
// Every method bypasses the HTTP session check — bus callers authenticate
// once, with the bootstrap token, and the connection is then trusted.
// cert.download returns private key material over that channel, so it is
// audited on every call with operator "bus".
const (
	MethodStats       = "cert.stats"
	MethodList        = "cert.list"
	MethodGet         = "cert.get"
	MethodCreate      = "cert.create"
	MethodUpdate      = "cert.update"
	MethodDelete      = "cert.delete"
	MethodRenew       = "cert.renew"
	MethodDeploy      = "cert.deploy"
	MethodDownload    = "cert.download"
	MethodInfo        = "cert.info"
	MethodEvents      = "cert.events"
	MethodDeployments = "cert.deployments"
	MethodDeployEvent = "cert.deploymentEvents"

	MethodAccounts      = "cert.acmeAccounts"
	MethodCreateAccount = "cert.createAcmeAccount"
	MethodUpdateAccount = "cert.updateAcmeAccount"
	MethodDeleteAccount = "cert.deleteAcmeAccount"
	MethodImportAccount = "cert.importAcmeAccount"

	MethodProviders      = "cert.dnsProviders"
	MethodCreateProvider = "cert.createDnsProvider"
	MethodUpdateProvider = "cert.updateDnsProvider"
	MethodDeleteProvider = "cert.deleteDnsProvider"

	MethodTargets      = "cert.deployTargets"
	MethodCreateTarget = "cert.createDeployTarget"
	MethodUpdateTarget = "cert.updateDeployTarget"
	MethodDeleteTarget = "cert.deleteDeployTarget"

	MethodLogs = "cert.logs"
)

// Methods lists everything this service advertises at bootstrap.
func Methods() []string {
	return []string{
		MethodStats, MethodList, MethodGet, MethodCreate, MethodUpdate,
		MethodDelete, MethodRenew, MethodDeploy, MethodDownload, MethodInfo,
		MethodEvents, MethodDeployments, MethodDeployEvent,
		MethodAccounts, MethodCreateAccount, MethodUpdateAccount,
		MethodDeleteAccount, MethodImportAccount,
		MethodProviders, MethodCreateProvider, MethodUpdateProvider, MethodDeleteProvider,
		MethodTargets, MethodCreateTarget, MethodUpdateTarget, MethodDeleteTarget,
		MethodLogs,
	}
}

// API is what the RPC layer needs from the application. It is deliberately
// narrow so the bus cannot reach past it.
type API interface {
	Store() db.Store
	Issue(ctx context.Context, certID int64, trigger string) error
	Deploy(ctx context.Context, certID int64, trigger string) error
}

// Handler dispatches bus RPC calls.
type Handler struct {
	App API
}

// okResult is what the methods that only succeed or fail return.
var okResult = map[string]string{"status": "ok"}

// idParams is the shape of every by-id call. The id must be a JSON number,
// matching the Rust implementation's behaviour.
type idParams struct {
	ID int64 `json:"id"`
}

func decodeParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func requireID(raw json.RawMessage) (int64, error) {
	var p idParams
	if err := decodeParams(raw, &p); err != nil {
		return 0, fmt.Errorf("invalid parameters: %w", err)
	}
	if p.ID == 0 {
		return 0, fmt.Errorf("missing 'id' parameter")
	}
	return p.ID, nil
}

// Dispatch routes one call.
func (h *Handler) Dispatch(ctx context.Context, method string, params json.RawMessage) (any, error) {
	store := h.App.Store()

	switch method {
	case MethodStats:
		return h.stats(ctx)

	case MethodList:
		var p struct {
			Search string `json:"search"`
			Status string `json:"status"`
		}
		// Bad parameters degrade to "no filter", matching the Rust
		// behaviour rather than failing the call.
		_ = decodeParams(params, &p)
		return store.ListCertificates(ctx, db.CertificateFilter{Search: p.Search, Status: p.Status})

	case MethodGet:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		return store.GetCertificate(ctx, id)

	case MethodCreate:
		var p struct {
			Domain          string   `json:"domain"`
			SANs            []string `json:"sans"`
			ACMEAccountID   int64    `json:"acmeAccountId"`
			DNSProviderID   int64    `json:"dnsProviderId"`
			ValidityDays    int64    `json:"validityDays"`
			DeployTargetIDs []int64  `json:"deployTargetIds"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		id, err := store.CreateCertificate(ctx, db.Certificate{
			Domain: p.Domain, SANs: p.SANs,
			ACMEAccountID: p.ACMEAccountID, DNSProviderID: p.DNSProviderID,
			ValidityDays: p.ValidityDays, AutoRenew: true,
		})
		if err != nil {
			return nil, err
		}
		if len(p.DeployTargetIDs) > 0 {
			if err := store.SetCertificateDeployTargets(ctx, id, p.DeployTargetIDs); err != nil {
				return nil, err
			}
		}
		go func() {
			// Issuance outlives the RPC, exactly as it outlives an HTTP
			// request.
			bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := h.App.Issue(bg, id, "bus"); err == nil {
				_ = h.App.Deploy(bg, id, "bus")
			}
		}()
		return store.GetCertificate(ctx, id)

	case MethodUpdate:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		var p struct {
			AutoRenew       *bool    `json:"autoRenew"`
			ValidityDays    *int64   `json:"validityDays"`
			DeployTargetIDs *[]int64 `json:"deployTargetIds"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if p.AutoRenew != nil || p.ValidityDays != nil {
			if err := store.UpdateCertificateSettings(ctx, id, db.CertificateSettings{
				AutoRenew: p.AutoRenew, ValidityDays: p.ValidityDays}); err != nil {
				return nil, err
			}
		}
		if p.DeployTargetIDs != nil {
			if err := store.SetCertificateDeployTargets(ctx, id, *p.DeployTargetIDs); err != nil {
				return nil, err
			}
		}
		return store.GetCertificate(ctx, id)

	case MethodDelete:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		if err := store.DeleteCertificate(ctx, id); err != nil {
			return nil, err
		}
		return okResult, nil

	case MethodRenew:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		go func() {
			bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			if err := h.App.Issue(bg, id, "bus"); err == nil {
				_ = h.App.Deploy(bg, id, "bus")
			}
		}()
		return okResult, nil

	case MethodDeploy:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		go func() {
			bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			_ = h.App.Deploy(bg, id, "bus")
		}()
		return okResult, nil

	case MethodDownload:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		cert, err := store.GetCertificate(ctx, id)
		if err != nil {
			return nil, err
		}
		if cert.Status != "issued" || cert.CertPEM == nil {
			return nil, fmt.Errorf("certificate %d has not been issued", id)
		}
		// This is the one method that hands out private key material, and
		// the bus is authenticated only by the bootstrap token, so leave a
		// trail attributable to the bus rather than to an operator.
		detail := "Downloaded certificate bundle for " + cert.Domain
		_ = store.AppendLog(ctx, db.OperationLog{
			Action: "download", ResourceType: "certificate",
			ResourceID: &id, Detail: &detail, Operator: "bus",
		})
		chain := ""
		if cert.ChainPEM != nil {
			chain = *cert.ChainPEM
		}
		return map[string]string{
			"domain":   cert.Domain,
			"certPem":  *cert.CertPEM,
			"chainPem": chain,
			"keyPem":   cert.KeyPEM,
		}, nil

	case MethodInfo:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		return store.GetCertificate(ctx, id)

	case MethodEvents:
		// Historically "the events for this certificate"; with the unified
		// runs/events model that is the events of its most recent run.
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		runs, err := store.ListRuns(ctx, id)
		if err != nil {
			return nil, err
		}
		if len(runs) == 0 {
			return []db.Event{}, nil
		}
		return store.ListRunEvents(ctx, runs[0].ID)

	case MethodDeployments:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		return store.ListDeployments(ctx, id)

	case MethodDeployEvent:
		// The id here is a deployment id, not a certificate id.
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		return store.ListRunEvents(ctx, id)

	case MethodAccounts:
		return store.ListACMEAccounts(ctx)

	case MethodCreateAccount, MethodImportAccount:
		return nil, fmt.Errorf("%s must be performed through the web API: it needs to talk to the CA interactively", method)

	case MethodUpdateAccount:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		var p struct {
			Name         *string `json:"name"`
			Email        *string `json:"email"`
			ValidityDays *int64  `json:"validityDays"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if err := store.UpdateACMEAccount(ctx, id, db.ACMEAccountUpdate{
			Name: p.Name, Email: p.Email, ValidityDays: p.ValidityDays,
		}); err != nil {
			return nil, err
		}
		return store.GetACMEAccount(ctx, id)

	case MethodDeleteAccount:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		if err := store.DeleteACMEAccount(ctx, id); err != nil {
			return nil, err
		}
		return okResult, nil

	case MethodProviders:
		// Masked here too: the bus reaches the same rows over a different
		// transport, and leaving it raw would have made the HTTP layer's
		// redaction cosmetic.
		providers, err := store.ListDNSProviders(ctx)
		if err != nil {
			return nil, err
		}
		for i := range providers {
			providers[i].Config = secret.Redact(providers[i].Config)
		}
		return providers, nil

	case MethodCreateProvider:
		var p namedParams
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		id, err := store.CreateDNSProvider(ctx, db.DNSProvider{
			Name: p.Name, Kind: p.Kind, Config: p.Config,
		})
		if err != nil {
			return nil, err
		}
		return store.GetDNSProvider(ctx, id)

	case MethodUpdateProvider:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		var p struct {
			Name   *string `json:"name"`
			Config *string `json:"config"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if err := store.UpdateDNSProvider(ctx, id, db.NamedUpdate{Name: p.Name, Config: p.Config}); err != nil {
			return nil, err
		}
		return store.GetDNSProvider(ctx, id)

	case MethodDeleteProvider:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		if err := store.DeleteDNSProvider(ctx, id); err != nil {
			return nil, err
		}
		return okResult, nil

	case MethodTargets:
		targets, err := store.ListDeployTargets(ctx)
		if err != nil {
			return nil, err
		}
		for i := range targets {
			targets[i].Config = secret.Redact(targets[i].Config)
		}
		return targets, nil

	case MethodCreateTarget:
		var p namedParams
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		id, err := store.CreateDeployTarget(ctx, db.DeployTarget{
			Name: p.Name, Kind: p.Kind, Config: p.Config,
		})
		if err != nil {
			return nil, err
		}
		return store.GetDeployTarget(ctx, id)

	case MethodUpdateTarget:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		var p struct {
			Name   *string `json:"name"`
			Config *string `json:"config"`
		}
		if err := decodeParams(params, &p); err != nil {
			return nil, err
		}
		if err := store.UpdateDeployTarget(ctx, id, db.NamedUpdate{Name: p.Name, Config: p.Config}); err != nil {
			return nil, err
		}
		return store.GetDeployTarget(ctx, id)

	case MethodDeleteTarget:
		id, err := requireID(params)
		if err != nil {
			return nil, err
		}
		if err := store.DeleteDeployTarget(ctx, id); err != nil {
			return nil, err
		}
		return okResult, nil

	case MethodLogs:
		var p struct {
			Limit  int `json:"limit"`
			Offset int `json:"offset"`
		}
		_ = decodeParams(params, &p)
		return store.ListLogs(ctx, p.Limit, p.Offset)

	default:
		return nil, fmt.Errorf("unknown method: %s", method)
	}
}

type namedParams struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Config string `json:"config"`
}

func (h *Handler) stats(ctx context.Context) (any, error) {
	store := h.App.Store()
	certs, err := store.ListCertificates(ctx, db.CertificateFilter{})
	if err != nil {
		return nil, err
	}
	accounts, err := store.ListACMEAccounts(ctx)
	if err != nil {
		return nil, err
	}
	targets, err := store.ListDeployTargets(ctx)
	if err != nil {
		return nil, err
	}

	var issued, failing int
	for _, c := range certs {
		switch c.Status {
		case "issued":
			issued++
		case "error":
			failing++
		}
	}
	return map[string]int{
		"totalCertificates":  len(certs),
		"issuedCertificates": issued,
		"failing":            failing,
		"acmeAccounts":       len(accounts),
		"deployTargets":      len(targets),
	}, nil
}
