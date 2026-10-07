// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package server implements the CertCenter backend: the JSON API, session
// auth, and the embedded SPA.
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/deploy"
	"github.com/mrhaoxx/certcenter/internal/issuance"
	"github.com/mrhaoxx/certcenter/web"
)

// Server carries the backend's dependencies. Later milestones add fields
// (issuer, deployer, bus) — Routes() is the single place they get wired
// into the HTTP surface.
type Server struct {
	DB       db.Store
	Sessions *SessionManager

	// Config reads the live configuration; the bus can swap it at runtime,
	// so handlers must call this per request rather than caching a copy.
	Config func() *config.Config

	// AllowedOrigins are the origins accepted for mutating requests.
	// Empty disables the check (single-origin deployments behind a proxy).
	AllowedOrigins map[string]bool
	SecureCookies  bool

	// ConfigPath is included in backups; empty omits it.
	ConfigPath string

	// Issuer obtains certificates; Deployer installs them. Both are nil in
	// the auth-only tests, and the handlers that need them say so.
	Issuer   *issuance.Issuer
	Deployer *deploy.Deployer

	// Events fans change signals out to the UI's SSE stream.
	Events *Broker

	// Running tracks cancellable work. Nil disables cancelling, which is
	// what the auth-only tests want.
	Running *running
}

// background returns a context for work that outlives the request that
// started it. Issuance takes minutes; tying it to the HTTP request would
// cancel it the moment the client got its 202.
func background() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Minute)
}

// apiError is the single error envelope for every API response.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (s *Server) writeErr(w http.ResponseWriter, status int, code, msg string, detail any) {
	s.writeJSON(w, status, apiError{Code: code, Message: msg, Detail: detail})
}

// Routes assembles the full handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	s.registerAuthRoutes(mux)
	s.registerCancelRoutes(mux)
	s.registerBackupRoutes(mux)
	s.registerResourceRoutes(mux)
	s.registerCertificateRoutes(mux)

	// Any unmatched /api/ path is a JSON 404, never an SPA fallback — a
	// mistyped endpoint must not return HTML to a fetch() caller.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		s.writeErr(w, http.StatusNotFound, "NOT_FOUND", "no such endpoint", nil)
	})

	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err) // the embed layout is fixed at build time
	}
	files := http.FileServerFS(dist)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A path containing "." is an asset request: serve it or 404.
		// Everything else is a client-side route: serve index.html.
		if strings.Contains(r.URL.Path, ".") {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFileFS(w, r, dist, "index.html")
	})

	return s.limitBody(s.originGuard(mux))
}

// maxRequestBody caps mutating request bodies so a huge or slowly
// dribbled payload can't exhaust memory or pin a goroutine.
const maxRequestBody = 256 << 10 // 256 KiB

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// limitBody bounds mutating request bodies. GET is untouched so it never
// interferes with the SSE stream added in milestone 4.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard rejects cross-origin mutating requests. Cookie auth needs
// this: without it any page could POST to the API with the user's cookie
// attached. A request with no Origin header (curl, a script) is allowed —
// browsers always send one on cross-origin writes.
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) && len(s.AllowedOrigins) > 0 {
			if o := r.Header.Get("Origin"); o != "" && !s.AllowedOrigins[o] {
				s.writeErr(w, http.StatusForbidden, "FORBIDDEN", "cross-origin request rejected", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sessionFrom authenticates the request. On failure it has already written
// the 401, so the caller just returns.
func (s *Server) sessionFrom(w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := ""
	if c, err := r.Cookie(SessionCookie); err == nil {
		token = c.Value
	} else if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
	}
	if token == "" {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "not logged in", nil)
		return Session{}, false
	}
	sess, err := s.Sessions.Verify(token, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session", nil)
		return Session{}, false
	}
	return sess, true
}

// requireSession wraps a handler so it only runs for an authenticated caller.
func (s *Server) requireSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionFrom(w, r); !ok {
			return
		}
		h(w, r)
	}
}

// decodeJSON reads a JSON body, rejecting unknown fields so a typo in a
// client payload fails loudly.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
