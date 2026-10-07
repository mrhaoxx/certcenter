// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/issuance"
)

func (s *Server) registerCertificateRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/certificates", s.requireSession(s.handleListCertificates))
	mux.HandleFunc("POST /api/certificates", s.requireSession(s.handleCreateCertificate))
	mux.HandleFunc("GET /api/certificates/{id}", s.requireSession(s.handleGetCertificate))
	mux.HandleFunc("PATCH /api/certificates/{id}", s.requireSession(s.handlePatchCertificate))
	mux.HandleFunc("DELETE /api/certificates/{id}", s.requireSession(s.handleDeleteCertificate))
	mux.HandleFunc("GET /api/certificates/{id}/x509", s.requireSession(s.handleCertificateX509))
	mux.HandleFunc("GET /api/certificates/{id}/bundle", s.requireSession(s.handleCertificateBundle))
	mux.HandleFunc("POST /api/certificates/{id}/renew", s.requireSession(s.handleRenewCertificate))
	mux.HandleFunc("POST /api/certificates/{id}/revoke", s.requireSession(s.handleRevokeCertificate))
	mux.HandleFunc("POST /api/certificates/{id}/pkcs12", s.requireSession(s.handleCertificatePKCS12))
	mux.HandleFunc("POST /api/certificates/{id}/deploy", s.requireSession(s.handleDeployCertificate))
	mux.HandleFunc("GET /api/certificates/{id}/deployments", s.requireSession(s.handleListCertDeployments))
	mux.HandleFunc("GET /api/certificates/{id}/runs", s.requireSession(s.handleListCertRuns))
	mux.HandleFunc("GET /api/runs/{id}/events", s.requireSession(s.handleRunEvents))
}

func (s *Server) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := s.DB.ListCertificates(r.Context(), db.CertificateFilter{
		Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		s.storeErr(w, err, "certificates")
		return
	}
	s.writeJSON(w, http.StatusOK, certs)
}

func (s *Server) handleGetCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}

	// The provider set lives in its own table, so the detail response
	// carries it alongside the row; the form needs it to render.
	providers, err := s.DB.ListCertificateDNSProviders(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns providers")
		return
	}
	ids := make([]int64, 0, len(providers))
	for _, p := range providers {
		ids = append(ids, p.ID)
	}
	s.writeJSON(w, http.StatusOK, struct {
		*db.Certificate
		DNSProviderIDs []int64 `json:"dnsProviderIds"`
	}{cert, ids})
}

type createCertificateRequest struct {
	Domain        string   `json:"domain"`
	SANs          []string `json:"sans"`
	ACMEAccountID int64    `json:"acmeAccountId"`
	DNSProviderID int64    `json:"dnsProviderId"`
	// DNSProviderIDs supersedes the singular field: a certificate can span
	// zones held at different providers. The singular one is still
	// accepted, and is what a single-provider request naturally sends.
	DNSProviderIDs   []int64 `json:"dnsProviderIds"`
	ValidityDays     int64   `json:"validityDays"`
	Profile          string  `json:"profile"`
	AutoRenew        *bool   `json:"autoRenew"`
	SkipDNSCheck     bool    `json:"skipDnsCheck"`
	RotateKey        bool    `json:"rotateKey"`
	KeyType          string  `json:"keyType"`
	PreferredChain   string  `json:"preferredChain"`
	NotBeforeDays    int64   `json:"notBeforeDays"`
	ExtendedKeyUsage string  `json:"extendedKeyUsage"`
	RenewBeforeDays  int64   `json:"renewBeforeDays"`
	CSRPEM           string  `json:"csrPem"`
	DeployTargetIDs  []int64 `json:"deployTargetIds"`
}

func (s *Server) handleCreateCertificate(w http.ResponseWriter, r *http.Request) {
	var req createCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Domain == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "domain is required", nil)
		return
	}
	// Check the references now so a certificate can never be created
	// pointing at an account or provider that does not exist.
	if _, err := s.DB.GetACMEAccount(r.Context(), req.ACMEAccountID); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "no such ACME account", nil)
		return
	}
	providerIDs := req.DNSProviderIDs
	if len(providerIDs) == 0 && req.DNSProviderID != 0 {
		providerIDs = []int64{req.DNSProviderID}
	}
	if len(providerIDs) == 0 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"at least one DNS provider is required", nil)
		return
	}
	for _, id := range providerIDs {
		if _, err := s.DB.GetDNSProvider(r.Context(), id); err != nil {
			s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
				fmt.Sprintf("no such DNS provider: %d", id), nil)
			return
		}
	}

	// A requested lifetime is per certificate and defaults to "don't ask".
	// It used to inherit the account's validity_days, which was a leftover
	// from when the value went nowhere; now it becomes the order's notAfter,
	// and Let's Encrypt rejects any order carrying one.
	validity := req.ValidityDays
	if validity < 0 {
		validity = 0
	}
	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}

	id, err := s.DB.CreateCertificate(r.Context(), db.Certificate{
		Domain: req.Domain, SANs: req.SANs,
		ACMEAccountID: req.ACMEAccountID, DNSProviderID: providerIDs[0],
		ValidityDays: validity, Profile: req.Profile, AutoRenew: autoRenew,
		SkipDNSCheck: req.SkipDNSCheck, RotateKey: req.RotateKey,
		KeyType: req.KeyType, PreferredChain: req.PreferredChain,
		NotBeforeDays: req.NotBeforeDays, ExtendedKeyUsage: req.ExtendedKeyUsage,
		RenewBeforeDays: req.RenewBeforeDays, CSRPEM: req.CSRPEM,
	})
	if err != nil {
		s.storeErr(w, err, "certificates")
		return
	}
	if err := s.DB.SetCertificateDNSProviders(r.Context(), id, providerIDs); err != nil {
		s.storeErr(w, err, "dns providers")
		return
	}
	if len(req.DeployTargetIDs) > 0 {
		if err := s.DB.SetCertificateDeployTargets(r.Context(), id, req.DeployTargetIDs); err != nil {
			s.storeErr(w, err, "deploy targets")
			return
		}
	}
	s.audit(r, "create", "certificate", id, "Created certificate for "+req.Domain)
	s.Events.Publish(TopicCertificates)

	s.startIssuance(id, "manual")

	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	s.writeJSON(w, http.StatusCreated, cert)
}

// startIssuance runs an issuance in the background.
//
// It gets its own context: issuance takes minutes, and tying it to the HTTP
// request would cancel it the moment the client receives its response.
func (s *Server) startIssuance(certID int64, trigger string) {
	if s.Issuer == nil {
		slog.Warn("no issuer configured; skipping issuance", "certificate", certID)
		return
	}
	// Tell the UI before the work starts. Issuance takes minutes, and
	// publishing only on completion left the page looking untouched until
	// it finished — the reason a manual refresh appeared to be required.
	s.Events.Publish(TopicCertificates)
	s.Events.Publish(TopicRuns)

	go func() {
		ctx, cancel := background()
		defer cancel()
		// Registered so a cancel request can reach this run. Issuance takes
		// minutes; without this the only way to stop one was to restart the
		// process, which left the run orphaned.
		if s.Running != nil {
			defer s.Running.add(certID, cancel)()
		}

		err := s.Issuer.Issue(ctx, certID, trigger)
		s.Events.Publish(TopicCertificates)
		s.Events.Publish(TopicRuns)
		if err != nil {
			// A cancellation is a decision, not a fault: logging it as a
			// failure would put it in the same list operators scan for
			// things that went wrong.
			action := "issue_failed"
			if cancelled(err) {
				action = "issue_cancelled"
				slog.Info("issuance cancelled", "certificate", certID)
			} else {
				slog.Warn("issuance failed", "certificate", certID, "err", err)
			}
			_ = s.DB.AppendLog(ctx, db.OperationLog{
				Action: action, ResourceType: "certificate",
				ResourceID: &certID, Detail: strPtr(err.Error()), Operator: "system",
			})
			s.Events.Publish(TopicLogs)
			return
		}
		_ = s.DB.AppendLog(ctx, db.OperationLog{
			Action: "issued", ResourceType: "certificate",
			ResourceID: &certID, Operator: "system",
		})
		s.Events.Publish(TopicLogs)

		// A fresh certificate is useless until it reaches the servers that
		// serve it, so deployment follows automatically.
		s.runDeployment(ctx, certID, "auto")
	}()
}

func (s *Server) runDeployment(ctx context.Context, certID int64, trigger string) {
	if s.Deployer == nil {
		return
	}
	if err := s.Deployer.DeployCertificate(ctx, certID, trigger); err != nil {
		slog.Warn("deployment failed", "certificate", certID, "err", err)
	}
	s.Events.Publish(TopicDeployments)
	s.Events.Publish(TopicRuns)
}

func strPtr(s string) *string { return &s }

func (s *Server) handlePatchCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		AutoRenew        *bool    `json:"autoRenew"`
		ValidityDays     *int64   `json:"validityDays"`
		Profile          *string  `json:"profile"`
		SkipDNSCheck     *bool    `json:"skipDnsCheck"`
		SkipDNSWait      **int64  `json:"skipDnsWaitSeconds"`
		RotateKey        *bool    `json:"rotateKey"`
		KeyType          *string  `json:"keyType"`
		PreferredChain   *string  `json:"preferredChain"`
		NotBeforeDays    *int64   `json:"notBeforeDays"`
		ExtendedKeyUsage *string  `json:"extendedKeyUsage"`
		RenewBeforeDays  *int64   `json:"renewBeforeDays"`
		ACMEAccountID    *int64   `json:"acmeAccountId"`
		DNSProviderIDs   *[]int64 `json:"dnsProviderIds"`
		DeployTargetIDs  *[]int64 `json:"deployTargetIds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if _, err := s.DB.GetCertificate(r.Context(), id); err != nil {
		s.storeErr(w, err, "certificate")
		return
	}

	// A different account means a different CA next time. The profile
	// stored here may not exist there, which acmez catches when the order
	// is placed rather than silently ignoring it.
	if req.ACMEAccountID != nil {
		if _, err := s.DB.GetACMEAccount(r.Context(), *req.ACMEAccountID); err != nil {
			s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "no such ACME account", nil)
			return
		}
	}

	settings := db.CertificateSettings{
		ACMEAccountID: req.ACMEAccountID,
		AutoRenew:     req.AutoRenew, ValidityDays: req.ValidityDays, Profile: req.Profile,
		SkipDNSCheck: req.SkipDNSCheck, SkipDNSWaitSeconds: req.SkipDNSWait,
		RotateKey: req.RotateKey, KeyType: req.KeyType, PreferredChain: req.PreferredChain,
		NotBeforeDays: req.NotBeforeDays, ExtendedKeyUsage: req.ExtendedKeyUsage,
		RenewBeforeDays: req.RenewBeforeDays,
	}
	{
		if err := s.DB.UpdateCertificateSettings(r.Context(), id, settings); err != nil {
			s.storeErr(w, err, "certificate")
			return
		}
	}
	if req.DNSProviderIDs != nil {
		if err := s.DB.SetCertificateDNSProviders(r.Context(), id, *req.DNSProviderIDs); err != nil {
			s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
			return
		}
	}
	if req.DeployTargetIDs != nil {
		if err := s.DB.SetCertificateDeployTargets(r.Context(), id, *req.DeployTargetIDs); err != nil {
			s.storeErr(w, err, "deploy targets")
			return
		}
		s.Events.Publish(TopicDeployments)
	}
	s.audit(r, "update", "certificate", id, "Updated certificate")
	s.Events.Publish(TopicCertificates)

	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}

	// The provider set lives in its own table, so the detail response
	// carries it alongside the row; the form needs it to render.
	providers, err := s.DB.ListCertificateDNSProviders(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "dns providers")
		return
	}
	ids := make([]int64, 0, len(providers))
	for _, p := range providers {
		ids = append(ids, p.ID)
	}
	s.writeJSON(w, http.StatusOK, struct {
		*db.Certificate
		DNSProviderIDs []int64 `json:"dnsProviderIds"`
	}{cert, ids})
}

func (s *Server) handleDeleteCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	// Deleting a certificate is meant to take its bindings, runs and events
	// with it — that history has no meaning without the certificate.
	if err := s.DB.DeleteCertificate(r.Context(), id); err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	s.audit(r, "delete", "certificate", id, "Deleted certificate for "+cert.Domain)
	s.Events.Publish(TopicCertificates)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRenewCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.DB.GetCertificate(r.Context(), id); err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	s.audit(r, "renew", "certificate", id, "Manual renewal triggered")
	s.startIssuance(id, "manual")
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleDeployCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	if cert.Status != "issued" {
		s.writeErr(w, http.StatusConflict, "NOT_ISSUED",
			"the certificate has not been issued yet", nil)
		return
	}
	s.audit(r, "deploy", "certificate", id, "Manual deployment triggered")
	go func() {
		ctx, cancel := background()
		defer cancel()
		s.runDeployment(ctx, id, "manual")
	}()
	w.WriteHeader(http.StatusAccepted)
}

// handleCertificateBundle is the only endpoint that returns private key
// material, so it is audited on every call.
func (s *Server) handleCertificateBundle(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	cert, err := s.DB.GetCertificate(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "certificate")
		return
	}
	if cert.Status != "issued" || cert.CertPEM == nil {
		s.writeErr(w, http.StatusConflict, "NOT_ISSUED",
			"the certificate has not been issued yet", nil)
		return
	}
	s.audit(r, "download", "certificate", id, "Downloaded certificate bundle for "+cert.Domain)

	chain := ""
	if cert.ChainPEM != nil {
		chain = *cert.ChainPEM
	}
	s.writeJSON(w, http.StatusOK, map[string]string{
		"domain":       cert.Domain,
		"certPem":      *cert.CertPEM,
		"chainPem":     chain,
		"keyPem":       cert.KeyPEM,
		"fullchainPem": fullChain(*cert.CertPEM, chain),
	})
}

func fullChain(leaf, chain string) string {
	if chain == "" {
		return leaf
	}
	if len(leaf) > 0 && leaf[len(leaf)-1] != '\n' {
		leaf += "\n"
	}
	return leaf + chain
}

func (s *Server) handleListCertDeployments(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	deployments, err := s.DB.ListDeployments(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "deployments")
		return
	}
	s.writeJSON(w, http.StatusOK, deployments)
}

func (s *Server) handleListCertRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	runs, err := s.DB.ListRuns(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "runs")
		return
	}
	s.writeJSON(w, http.StatusOK, runs)
}

func (s *Server) handleRunEvents(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "invalid run id", nil)
		return
	}
	events, err := s.DB.ListRunEvents(r.Context(), id)
	if err != nil {
		s.storeErr(w, err, "run events")
		return
	}
	s.writeJSON(w, http.StatusOK, events)
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

// handleRevokeCertificate asks the CA to revoke, synchronously.
//
// Unlike issuance this is quick and its outcome is the whole point — an
// operator revoking a leaked key needs to know it worked, not get a 202
// and go looking for the result.
func (s *Server) handleRevokeCertificate(w http.ResponseWriter, r *http.Request) {
	id, ok := s.pathID(w, r)
	if !ok {
		return
	}
	var req revokeRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if req.Reason == "" {
		req.Reason = "unspecified"
	}
	if _, known := issuance.RevocationReasons[req.Reason]; !known {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"unknown revocation reason", issuance.RevocationReasonNames())
		return
	}
	if s.Issuer == nil {
		s.writeErr(w, http.StatusNotImplemented, "UNSUPPORTED", "no issuer configured", nil)
		return
	}

	if err := s.Issuer.Revoke(r.Context(), id, req.Reason); err != nil {
		s.writeErr(w, http.StatusBadGateway, "CA_ERROR",
			"the certificate could not be revoked", err.Error())
		return
	}
	s.audit(r, "revoke", "certificate", id, "Revoked: "+req.Reason)
	s.Events.Publish(TopicCertificates)
	w.WriteHeader(http.StatusNoContent)
}
