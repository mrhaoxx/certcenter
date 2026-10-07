// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// bcryptCost is deliberately above bcrypt.DefaultCost (10). Spec §6 fixes
// it at 12; keep the constant so hashing and the tests can never drift.
const bcryptCost = 12

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.requireSession(s.handleMe))
	mux.HandleFunc("PUT /api/me/password", s.requireSession(s.handleChangePassword))
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}

	cfg := s.Config()
	hash, err := s.DB.GetSetting(r.Context(), db.SettingAdminPasswordHash)
	if err != nil {
		// SeedAdminPassword runs at startup, so a missing hash means the
		// service is misconfigured rather than the caller being wrong.
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not read credentials", nil)
		return
	}

	// Evaluate both factors unconditionally: bcrypt runs even when the
	// username is wrong, so response timing does not reveal which half
	// failed. (Short-circuiting on the username would make a valid
	// username measurably slower.)
	passwordOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) == nil
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfg.Auth.Username)) == 1
	if !passwordOK || !userOK {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid username or password", nil)
		return
	}

	token, err := s.Sessions.Issue(cfg.Auth.Username, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not issue a session", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.Sessions.TTL().Seconds()),
	})
	s.writeJSON(w, http.StatusOK, map[string]string{"user": cfg.Auth.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	// Sessions are stateless, so logout is just dropping the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFrom(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"user": sess.User,
	})
}

// minPasswordLength is the floor for a new password.
const minPasswordLength = 8

// SeedAdminPassword writes the config's bcrypt hash into settings the
// first time the service starts. It never overwrites an existing value:
// once the admin changes their password through the API, the hash in
// config.toml is stale and must not win on the next restart.
func SeedAdminPassword(ctx context.Context, store db.Store, configHash string) error {
	if _, err := store.GetSetting(ctx, db.SettingAdminPasswordHash); err == nil {
		return nil // already seeded
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	if configHash == "" {
		return errors.New("auth.password_hash is empty and no password is stored; cannot seed the admin account")
	}
	return store.SetSetting(ctx, db.SettingAdminPasswordHash, configHash)
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			fmt.Sprintf("the new password must be at least %d characters", minPasswordLength), nil)
		return
	}

	current, err := s.DB.GetSetting(r.Context(), db.SettingAdminPasswordHash)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not read credentials", nil)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(current), []byte(req.OldPassword)) != nil {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "current password is incorrect", nil)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not hash the password", nil)
		return
	}
	if err := s.DB.SetSetting(r.Context(), db.SettingAdminPasswordHash, string(hash)); err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not store the password", nil)
		return
	}
	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "change_password", ResourceType: "auth", Operator: "admin",
	})
	w.WriteHeader(http.StatusNoContent)
}
