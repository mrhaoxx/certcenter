// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/deploy"
	"github.com/mrhaoxx/certcenter/internal/dns"
	"github.com/mrhaoxx/certcenter/internal/issuance"
	"github.com/mrhaoxx/certcenter/internal/secret"
)

// Every path that hands a provider or target to a client masks its config
// first. TestNoEndpointLeaksSecrets walks all of them and fails if a
// credential ever reaches the wire again.

func redactedProvider(p *db.DNSProvider) db.DNSProvider {
	out := *p
	out.Config = secret.Redact(out.Config)
	return out
}

func redactedProviders(in []db.DNSProvider) []db.DNSProvider {
	out := make([]db.DNSProvider, len(in))
	for i, p := range in {
		out[i] = redactedProvider(&p)
	}
	return out
}

func redactedTarget(t *db.DeployTarget) db.DeployTarget {
	out := *t
	out.Config = secret.Redact(out.Config)
	return out
}

func redactedTargets(in []db.DeployTarget) []db.DeployTarget {
	out := make([]db.DeployTarget, len(in))
	for i, t := range in {
		out[i] = redactedTarget(&t)
	}
	return out
}

func (s *Server) registerResourceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/dashboard", s.requireSession(s.handleDashboard))
	mux.HandleFunc("GET /api/events", s.requireSession(s.handleEvents))
	mux.HandleFunc("GET /api/logs", s.requireSession(s.handleLogs))

	mux.HandleFunc("GET /api/acme-accounts", s.requireSession(s.handleListAccounts))
	mux.HandleFunc("POST /api/acme-accounts", s.requireSession(s.handleCreateAccount))
	mux.HandleFunc("POST /api/acme-accounts/import", s.requireSession(s.handleImportAccount))
	mux.HandleFunc("PATCH /api/acme-accounts/{id}", s.requireSession(s.handlePatchAccount))
	mux.HandleFunc("DELETE /api/acme-accounts/{id}", s.requireSession(s.handleDeleteAccount))
	mux.HandleFunc("GET /api/acme-accounts/{id}/profiles", s.requireSession(s.handleAccountProfiles))
	mux.HandleFunc("POST /api/acme-directory", s.requireSession(s.handleProbeDirectory))
	mux.HandleFunc("GET /api/settings/dns", s.requireSession(s.handleGetDNSSettings))
	mux.HandleFunc("PUT /api/settings/dns", s.requireSession(s.handlePutDNSSettings))

	mux.HandleFunc("GET /api/dns-providers", s.requireSession(s.handleListDNSProviders))
	mux.HandleFunc("POST /api/dns-providers", s.requireSession(s.handleCreateDNSProvider))
	mux.HandleFunc("PATCH /api/dns-providers/{id}", s.requireSession(s.handlePatchDNSProvider))
	mux.HandleFunc("DELETE /api/dns-providers/{id}", s.requireSession(s.handleDeleteDNSProvider))

	mux.HandleFunc("GET /api/deploy-targets", s.requireSession(s.handleListDeployTargets))
	mux.HandleFunc("POST /api/deploy-targets", s.requireSession(s.handleCreateDeployTarget))
	mux.HandleFunc("PATCH /api/deploy-targets/{id}", s.requireSession(s.handlePatchDeployTarget))
	mux.HandleFunc("DELETE /api/deploy-targets/{id}", s.requireSession(s.handleDeleteDeployTarget))
}

// pathID parses the {id} path value, writing the 400 itself on failure.
func (s *Server) pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid id", nil)
		return 0, false
	}
	return id, true
}

// storeErr maps a store error onto the right status. ErrNotFound is a 404;
// anything else is ours, not the caller's.
func (s *Server) storeErr(w http.ResponseWriter, err error, what string) {
	if errors.Is(err, db.ErrNotFound) {
		s.writeErr(w, http.StatusNotFound, "NOT_FOUND", "no such "+what, nil)
		return
	}
	s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not access "+what, nil)
}

// audit records an operator action. A failure to write the audit log must
// not fail the request that succeeded.
func (s *Server) audit(r *http.Request, action, resourceType string, resourceID int64, detail string) {
	entry := db.OperationLog{Action: action, ResourceType: resourceType, Operator: "admin"}
	if resourceID != 0 {
		entry.ResourceID = &resourceID
	}
	if detail != "" {
		entry.Detail = &detail
	}
	_ = s.DB.AppendLog(r.Context(), entry)
	s.Events.Publish(TopicLogs)
}

// ── dashboard ──────────────────────────────────────────────────────────

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	certs, err := s.DB.ListCertificates(r.Context(), db.CertificateFilter{})
	if err != nil {
		s.storeErr(w, err, "certificates")
		return
	}
	accounts, err := s.DB.ListACMEAccounts(r.Context())
	if err != nil {
		s.storeErr(w, err, "accounts")
		return
	}
	targets, err := s.DB.ListDeployTargets(r.Context())
	if err != nil {
		s.storeErr(w, err, "deploy targets")
		return
	}

	var issued, expiring, expired, failing int
	now := time.Now()
	for _, c := range certs {
		switch c.Status {
		case "issued":
			issued++
		case "error":
			failing++
		}
		if c.NotAfter == nil {
			continue
		}
		notAfter, err := time.Parse(time.RFC3339, *c.NotAfter)
		if err != nil {
			continue
		}
		switch {
		case !notAfter.After(now):
			expired++
		// "Expiring" is the last 20% of the certificate's own lifetime,
		// the same threshold the renewal scheduler uses, so the dashboard
		// and the scheduler never disagree.
		case notAfter.Sub(now) <= time.Duration(float64(c.ValidityDays)*0.2*24)*time.Hour:
			expiring++
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"totalCertificates":  len(certs),
		"issuedCertificates": issued,
		"expiringSoon":       expiring,
		"expired":            expired,
		"failing":            failing,
		"acmeAccounts":       len(accounts),
		"deployTargets":      len(targets),
	})
}

// ── operation log ──────────────────────────────────────────────────────

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	logs, err := s.DB.ListLogs(r.Context(), limit, offset)
	if err != nil {
		s.storeErr(w, err, "logs")
		return
	}
	s.writeJSON(w, http.StatusOK, logs)
}

// ── ACME accounts ──────────────────────────────────────────────────────

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.DB.ListACMEAccounts(r.Context())
	if err != nil {
		s.storeErr(w, err, "accounts")
		return
	}
	s.writeJSON(w, http.StatusOK, accounts)
}

type createAccountRequest struct {
	Name         string `json:"name"`
	DirectoryURL string `json:"directoryUrl"`
	Email        string `json:"email"`
	ValidityDays int64  `json:"validityDays"`
	// Some CAs (ZeroSSL, Google, Sectigo) require external account
	// binding; Let's Encrypt does not.
	EABKeyID  string `json:"eabKeyId"`
	EABMACKey string `json:"eabMacKey"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Name == "" || req.DirectoryURL == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "name and directoryUrl are required", nil)
		return
	}

	keyPEM, err := issuance.GenerateAccountKey()
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not generate an account key", nil)
		return
	}
	// Registering before storing means a directory URL that does not answer
	// never becomes a half-configured row.
	accountURL, err := s.registrar().Register(r.Context(), issuance.Registration{
		DirectoryURL: req.DirectoryURL, Email: req.Email, KeyPEM: keyPEM,
		EABKeyID: req.EABKeyID, EABMACKey: req.EABMACKey,
	})
	if err != nil {
		// Distinguish "this CA needs external account binding" from every
		// other rejection: it is the one failure the operator can fix
		// themselves, by pasting the credentials the CA issued them.
		if issuance.RequiresEAB(err) {
			s.writeErr(w, http.StatusBadRequest, "EAB_REQUIRED",
				"this certificate authority requires external account binding; "+
					"provide the key ID and HMAC key from your account with them",
				err.Error())
			return
		}
		s.writeErr(w, http.StatusBadGateway, "CA_ERROR",
			"the certificate authority rejected the registration", err.Error())
		return
	}

	id, err := s.DB.CreateACMEAccount(r.Context(), db.ACMEAccount{
		Name: req.Name, DirectoryURL: req.DirectoryURL, Email: req.Email,
		AccountURL: &accountURL, PrivateKeyPEM: keyPEM, ValidityDays: req.ValidityDays,
	})
	if err != nil {
		s.storeErr(w, err, "accounts")
		return
	}
	s.audit(r, "create", "acme_account", id, "Registered ACME account: "+req.Name)
	s.Events.Publish(TopicAccounts)

	account, err := s.DB.GetACMEAccount(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	s.writeJSON(w, http.StatusCreated, account)
}

type importAccountRequest struct {
	Name          string `json:"name"`
	DirectoryURL  string `json:"directoryUrl"`
	Email         string `json:"email"`
	AccountURL    string `json:"accountUrl"`
	PrivateKeyPEM string `json:"privateKeyPem"`
	ValidityDays  int64  `json:"validityDays"`
}

func (s *Server) handleImportAccount(w http.ResponseWriter, r *http.Request) {
	var req importAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Name == "" || req.DirectoryURL == "" || req.AccountURL == "" || req.PrivateKeyPEM == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"name, directoryUrl, accountUrl and privateKeyPem are required", nil)
		return
	}

	// Verify the pair against the CA rather than trusting what was typed,
	// so a bad import fails here instead of at the first issuance.
	if err := s.registrar().Verify(r.Context(), req.DirectoryURL, req.AccountURL, req.PrivateKeyPEM); err != nil {
		s.writeErr(w, http.StatusBadRequest, "INVALID_ACCOUNT",
			"the CA did not accept this key and account URL", err.Error())
		return
	}

	id, err := s.DB.CreateACMEAccount(r.Context(), db.ACMEAccount{
		Name: req.Name, DirectoryURL: req.DirectoryURL, Email: req.Email,
		AccountURL: &req.AccountURL, PrivateKeyPEM: req.PrivateKeyPEM,
		ValidityDays: req.ValidityDays,
	})
	if err != nil {
		s.storeErr(w, err, "accounts")
		return
	}
	s.audit(r, "import", "acme_account", id, "Imported ACME account: "+req.Name)
	s.Events.Publish(TopicAccounts)

	account, err := s.DB.GetACMEAccount(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	s.writeJSON(w, http.StatusCreated, account)
}

func (s *Server) registrar() *issuance.Registrar {
	if s.Issuer != nil && s.Issuer.Registrar != nil {
		return s.Issuer.Registrar
	}
	return &issuance.Registrar{}
}

func (s *Server) handlePatchAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name         *string `json:"name"`
		Email        *string `json:"email"`
		ValidityDays *int64  `json:"validityDays"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	err := s.DB.UpdateACMEAccount(r.Context(), id, db.ACMEAccountUpdate{
		Name: req.Name, Email: req.Email, ValidityDays: req.ValidityDays,
	})
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	s.audit(r, "update", "acme_account", id, "Updated ACME account")
	s.Events.Publish(TopicAccounts)

	account, err := s.DB.GetACMEAccount(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	s.writeJSON(w, http.StatusOK, account)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	// Refuse rather than cascade: silently deleting an account would take
	// its certificates' issuance history with it.
	n, err := s.DB.CountCertificatesUsingACMEAccount(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	if n > 0 {
		s.writeErr(w, http.StatusConflict, "IN_USE",
			"this account is still used by certificates",
			map[string]int{"certificates": n})
		return
	}
	if err := s.DB.DeleteACMEAccount(r.Context(), id); err != nil {
		s.storeErr(w, err, "account")
		return
	}
	s.audit(r, "delete", "acme_account", id, "Deleted ACME account")
	s.Events.Publish(TopicAccounts)
	w.WriteHeader(http.StatusNoContent)
}

// ── DNS providers ──────────────────────────────────────────────────────

func (s *Server) handleListDNSProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := s.DB.ListDNSProviders(r.Context())
	if err != nil {
		s.storeErr(w, err, "dns providers")
		return
	}
	s.writeJSON(w, http.StatusOK, redactedProviders(providers))
}

type namedResourceRequest struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Config string `json:"config"`
}

func (s *Server) handleCreateDNSProvider(w http.ResponseWriter, r *http.Request) {
	var req namedResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Name == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "name is required", nil)
		return
	}
	// Building the provider validates the credentials' shape now rather
	// than at 2am when a renewal fails.
	if _, err := dns.New(req.Kind, req.Config); err != nil {
		s.writeErr(w, http.StatusBadRequest, "INVALID_CONFIG", err.Error(),
			map[string]any{"supportedKinds": dns.Kinds()})
		return
	}

	id, err := s.DB.CreateDNSProvider(r.Context(), db.DNSProvider{
		Name: req.Name, Kind: req.Kind, Config: req.Config,
	})
	if err != nil {
		s.storeErr(w, err, "dns providers")
		return
	}
	s.audit(r, "create", "dns_provider", id, "Created DNS provider: "+req.Name)
	s.Events.Publish(TopicProviders)

	provider, err := s.DB.GetDNSProvider(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	s.writeJSON(w, http.StatusCreated, redactedProvider(provider))
}

func (s *Server) handlePatchDNSProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name   *string `json:"name"`
		Config *string `json:"config"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}

	existing, err := s.DB.GetDNSProvider(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	if req.Config != nil {
		// The form only ever saw a mask, so put the stored secrets back
		// before validating — otherwise editing a name would blank the
		// credential the operator was never shown.
		merged := secret.Restore(*req.Config, existing.Config)
		req.Config = &merged
		if _, err := dns.New(existing.Kind, merged); err != nil {
			s.writeErr(w, http.StatusBadRequest, "INVALID_CONFIG", err.Error(), nil)
			return
		}
	}
	if err := s.DB.UpdateDNSProvider(r.Context(), id, db.NamedUpdate{Name: req.Name, Config: req.Config}); err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	s.audit(r, "update", "dns_provider", id, "Updated DNS provider")
	s.Events.Publish(TopicProviders)

	provider, err := s.DB.GetDNSProvider(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	s.writeJSON(w, http.StatusOK, redactedProvider(provider))
}

func (s *Server) handleDeleteDNSProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	n, err := s.DB.CountCertificatesUsingDNSProvider(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	if n > 0 {
		s.writeErr(w, http.StatusConflict, "IN_USE",
			"this provider is still used by certificates",
			map[string]int{"certificates": n})
		return
	}
	if err := s.DB.DeleteDNSProvider(r.Context(), id); err != nil {
		s.storeErr(w, err, "dns provider")
		return
	}
	s.audit(r, "delete", "dns_provider", id, "Deleted DNS provider")
	s.Events.Publish(TopicProviders)
	w.WriteHeader(http.StatusNoContent)
}

// ── deploy targets ─────────────────────────────────────────────────────

func (s *Server) handleListDeployTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := s.DB.ListDeployTargets(r.Context())
	if err != nil {
		s.storeErr(w, err, "deploy targets")
		return
	}
	s.writeJSON(w, http.StatusOK, redactedTargets(targets))
}

func (s *Server) handleCreateDeployTarget(w http.ResponseWriter, r *http.Request) {
	var req namedResourceRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Name == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "name is required", nil)
		return
	}
	// The Rust implementation validated nothing at write time, so a broken
	// pipeline only surfaced during a deployment.
	if _, err := deploy.New(req.Kind, req.Config, deploy.Options{ManagementURL: "validate"}); err != nil {
		s.writeErr(w, http.StatusBadRequest, "INVALID_CONFIG", err.Error(),
			map[string]any{"supportedKinds": deploy.Kinds()})
		return
	}

	id, err := s.DB.CreateDeployTarget(r.Context(), db.DeployTarget{
		Name: req.Name, Kind: req.Kind, Config: req.Config,
	})
	if err != nil {
		s.storeErr(w, err, "deploy targets")
		return
	}
	s.audit(r, "create", "deploy_target", id, "Created deploy target: "+req.Name)
	s.Events.Publish(TopicTargets)

	target, err := s.DB.GetDeployTarget(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	s.writeJSON(w, http.StatusCreated, redactedTarget(target))
}

func (s *Server) handlePatchDeployTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Name   *string `json:"name"`
		Config *string `json:"config"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}

	existing, err := s.DB.GetDeployTarget(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	if req.Config != nil {
		// See the DNS provider update: the form only saw masks, so the
		// stored secrets go back before anything is validated or written.
		merged := secret.Restore(*req.Config, existing.Config)
		req.Config = &merged
		if _, err := deploy.New(existing.Kind, merged, deploy.Options{ManagementURL: "validate"}); err != nil {
			s.writeErr(w, http.StatusBadRequest, "INVALID_CONFIG", err.Error(), nil)
			return
		}
	}
	if err := s.DB.UpdateDeployTarget(r.Context(), id, db.NamedUpdate{Name: req.Name, Config: req.Config}); err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	s.audit(r, "update", "deploy_target", id, "Updated deploy target")
	s.Events.Publish(TopicTargets)

	target, err := s.DB.GetDeployTarget(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	s.writeJSON(w, http.StatusOK, redactedTarget(target))
}

func (s *Server) handleDeleteDeployTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	n, err := s.DB.CountDeploymentsUsingTarget(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	if n > 0 {
		s.writeErr(w, http.StatusConflict, "IN_USE",
			"this target is still bound to certificates",
			map[string]int{"deployments": n})
		return
	}
	if err := s.DB.DeleteDeployTarget(r.Context(), id); err != nil {
		s.storeErr(w, err, "deploy target")
		return
	}
	s.audit(r, "delete", "deploy_target", id, "Deleted deploy target")
	s.Events.Publish(TopicTargets)
	w.WriteHeader(http.StatusNoContent)
}

// handleAccountProfiles reports the ACME profiles this account's CA offers.
//
// The UI populates its picker from here rather than from a hard-coded list,
// because the set is per-CA and changes without us.
func (s *Server) handleAccountProfiles(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	account, err := s.DB.GetACMEAccount(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "account")
		return
	}
	profiles, err := s.registrar().Profiles(r.Context(), account.DirectoryURL)
	if err != nil {
		s.writeErr(w, http.StatusBadGateway, "CA_ERROR",
			"could not read the certificate authority's directory", err.Error())
		return
	}
	if profiles == nil {
		profiles = map[string]string{}
	}
	s.writeJSON(w, http.StatusOK, profiles)
}

type probeDirectoryRequest struct {
	DirectoryURL string `json:"directoryUrl"`
}

// handleProbeDirectory reports what a CA's directory advertises, so the
// new-account form can adapt to the chosen CA instead of relying on a
// hard-coded table that drifts.
//
// The URL is supplied by the caller, which makes this a fetch the server
// performs on request. It is admin-only, restricted to https, and returns
// only parsed ACME directory fields — never the raw response — so it is a
// poor instrument for probing anything that is not an ACME directory.
func (s *Server) handleProbeDirectory(w http.ResponseWriter, r *http.Request) {
	var req probeDirectoryRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if !strings.HasPrefix(req.DirectoryURL, "https://") {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"the directory URL must start with https://", nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	caps, err := s.registrar().Probe(ctx, req.DirectoryURL)
	if err != nil {
		s.writeErr(w, http.StatusBadGateway, "CA_ERROR",
			"could not read the certificate authority's directory", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, caps)
}

// dnsSettingsStore is the part of the store these handlers need. The
// backup handler had to type-assert to *db.SQLite for the same reason;
// narrowing to what is used keeps that from spreading.
type dnsSettingsStore interface {
	GetDNSSettings(ctx context.Context, fallback db.DNSSettings) (db.DNSSettings, error)
	PutDNSSettings(ctx context.Context, v db.DNSSettings) error
}

// dnsFallback is what the settings default to before anything is stored:
// the values from config.toml, or the package defaults if it is silent.
func (s *Server) dnsFallback() db.DNSSettings {
	c := s.Config()
	return db.DNSSettings{
		Server:  c.DoHServer(),
		Retries: c.DNSMaxRetries(),
		Skip:    c.DNSVerification.Skip,
	}
}

func (s *Server) handleGetDNSSettings(w http.ResponseWriter, r *http.Request) {
	store, ok := s.DB.(dnsSettingsStore)
	if !ok {
		s.writeErr(w, http.StatusNotImplemented, "UNSUPPORTED", "this store has no settings", nil)
		return
	}
	v, err := store.GetDNSSettings(r.Context(), s.dnsFallback())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not read the settings", nil)
		return
	}
	s.writeJSON(w, http.StatusOK, v)
}

func (s *Server) handlePutDNSSettings(w http.ResponseWriter, r *http.Request) {
	store, ok := s.DB.(dnsSettingsStore)
	if !ok {
		s.writeErr(w, http.StatusNotImplemented, "UNSUPPORTED", "this store has no settings", nil)
		return
	}
	var req db.DNSSettings
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	// A resolver reached over plain HTTP would leak which names are being
	// validated, and could be answered by anyone on the path — the check
	// exists to be trusted.
	if !strings.HasPrefix(req.Server, "https://") {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"the DoH server must be an https:// URL", nil)
		return
	}
	if req.Retries < 1 || req.Retries > 60 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"retries must be between 1 and 60", nil)
		return
	}
	if req.SkipWaitSeconds < 0 || req.SkipWaitSeconds > 600 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"the wait must be between 0 and 600 seconds", nil)
		return
	}
	if err := store.PutDNSSettings(r.Context(), req); err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not store the settings", nil)
		return
	}
	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "update_dns_settings", ResourceType: "settings", Operator: "admin",
	})
	s.writeJSON(w, http.StatusOK, req)
}
