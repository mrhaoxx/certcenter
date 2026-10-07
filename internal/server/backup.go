// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mrhaoxx/certcenter/internal/backup"
	"github.com/mrhaoxx/certcenter/internal/db"
)

func (s *Server) registerBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/backup", s.requireSession(s.handleBackup))
	mux.HandleFunc("POST /api/backup/restore", s.requireSession(s.handleRestore))
}

type backupRequest struct {
	Passphrase string `json:"passphrase"`
}

// handleBackup streams an encrypted snapshot of everything the service
// cannot regenerate.
//
// The passphrase arrives per request and is never stored. That is the
// difference between this and an unattended backup: a cron job would have
// to keep a key readable by the host, which is exactly the situation a
// backup exists to survive. Here the operator supplies it live.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	var req backupRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if len(req.Passphrase) < backup.MinPassphraseLength {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"the passphrase must be at least 12 characters", nil)
		return
	}

	sqlite, ok := s.DB.(*db.SQLite)
	if !ok {
		s.writeErr(w, http.StatusNotImplemented, "UNSUPPORTED",
			"this store does not support snapshots", nil)
		return
	}

	now := time.Now()
	name := backup.Filename(now)

	// Headers go out before the body starts. Once bytes are on the wire the
	// status is fixed, so a mid-stream failure can only be logged and the
	// connection cut — the client sees a truncated file, which age refuses
	// to decrypt rather than silently accepting.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")

	manifest, err := backup.Create(r.Context(), sqlite.DB, s.ConfigPath, req.Passphrase, w, now)
	if err != nil {
		slog.Error("backup failed", "err", err)
		return
	}

	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "backup", ResourceType: "system", Operator: "admin",
		Detail: strPtr(manifestSummary(manifest)),
	})
	slog.Info("backup downloaded", "accounts", manifest.ACMEAccounts,
		"certificates", manifest.Certificates, "config", manifest.HasConfig)
}

func manifestSummary(m backup.Manifest) string {
	return fmt.Sprintf("accounts=%d providers=%d targets=%d certificates=%d",
		m.ACMEAccounts, m.DNSProviders, m.DeployTarget, m.Certificates)
}

// maxArchive bounds an uploaded backup. The archive is a compressed
// database; anything far larger is a mistake or an attempt to exhaust the
// disk unpacking it.
const maxArchive = 256 << 20 // 256 MiB

// handleRestore replaces the live data from an uploaded archive.
//
// This runs against the database the process is using rather than swapping
// the file: the service holds it open in WAL mode, so a replacement would
// need a restart at best. The rows move inside one transaction, which is
// also what keeps a failure from leaving the service with nothing — every
// table is emptied before any is refilled.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	sqlite, ok := s.DB.(*db.SQLite)
	if !ok {
		s.writeErr(w, http.StatusNotImplemented, "UNSUPPORTED",
			"this store does not support restoring", nil)
		return
	}

	// The upload is multipart because the archive is binary and can be
	// tens of megabytes; base64 in JSON would inflate it for no reason.
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			"expected a multipart upload with an archive and a passphrase", nil)
		return
	}
	passphrase := r.FormValue("passphrase")
	if passphrase == "" {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "the passphrase is required", nil)
		return
	}
	file, header, err := r.FormFile("archive")
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "no archive was uploaded", nil)
		return
	}
	defer file.Close()
	if header.Size > maxArchive {
		s.writeErr(w, http.StatusRequestEntityTooLarge, "TOO_LARGE",
			"the archive is larger than this accepts", nil)
		return
	}

	report, err := backup.Restore(r.Context(), sqlite.DB, io.LimitReader(file, maxArchive), passphrase)
	if err != nil {
		// Nothing was changed: the restore either commits whole or not at
		// all, and the checks that reject an archive run before the
		// transaction opens.
		s.writeErr(w, http.StatusBadRequest, "RESTORE_FAILED", err.Error(), nil)
		return
	}

	slog.Warn("data restored from a backup",
		"createdAt", report.Manifest.CreatedAt, "rows", report.Rows)
	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "restore", ResourceType: "system", Operator: "admin",
		Detail: strPtr("restored an archive created " + report.Manifest.CreatedAt),
	})
	// Everything the UI shows came from tables that were just replaced.
	for _, topic := range []string{TopicCertificates, TopicAccounts, TopicProviders,
		TopicTargets, TopicRuns, TopicDeployments, TopicLogs} {
		s.Events.Publish(topic)
	}
	s.writeJSON(w, http.StatusOK, report)
}
