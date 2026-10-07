// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"strconv"
)

// DNS verification setting keys. config.toml seeds these on first boot and
// the database is authoritative afterwards — the same arrangement as the
// admin password, and for the same reason: an operator should be able to
// change a running service without editing a file inside a container.
const (
	SettingDoHServer   = "doh_server"
	SettingDoHRetries  = "doh_max_retries"
	SettingDoHSkip     = "doh_skip"
	SettingDoHSkipWait = "doh_skip_wait_seconds"
)

// DNSSettings controls the propagation check performed before a challenge
// is handed to the CA.
type DNSSettings struct {
	Server  string `json:"server"`
	Retries int    `json:"retries"`
	// Skip disables the check for every certificate. A single zone that our
	// resolver cannot see is better handled by the per-certificate switch.
	Skip bool `json:"skip"`
	// SkipWaitSeconds is how long to wait instead of checking. Handing the
	// challenge over the instant the record is written means the CA does
	// the discovering, and its failure arrives later and reads worse than
	// our own. Waiting blind is a poor substitute for looking, but it beats
	// not waiting at all.
	SkipWaitSeconds int `json:"skipWaitSeconds"`
}

// DefaultSkipWaitSeconds is the blind wait used when the check is off.
const DefaultSkipWaitSeconds = 30

// GetDNSSettings reads the stored settings, falling back to the supplied
// defaults for any key that has never been written.
func (s *SQLite) GetDNSSettings(ctx context.Context, fallback DNSSettings) (DNSSettings, error) {
	out := fallback

	if v, err := s.GetSetting(ctx, SettingDoHServer); err == nil {
		out.Server = v
	} else if !errors.Is(err, ErrNotFound) {
		return out, err
	}
	if v, err := s.GetSetting(ctx, SettingDoHRetries); err == nil {
		if n, convErr := strconv.Atoi(v); convErr == nil && n > 0 {
			out.Retries = n
		}
	} else if !errors.Is(err, ErrNotFound) {
		return out, err
	}
	if v, err := s.GetSetting(ctx, SettingDoHSkip); err == nil {
		out.Skip = v == "true"
	} else if !errors.Is(err, ErrNotFound) {
		return out, err
	}
	// A row written before this field existed stores nothing for it, and an
	// instance that had ever saved DNS settings would otherwise read zero
	// — silently opting out of the wait that new installs get.
	if v, err := s.GetSetting(ctx, SettingDoHSkipWait); err == nil {
		if n, convErr := strconv.Atoi(v); convErr == nil && n >= 0 {
			out.SkipWaitSeconds = n
		}
	} else if errors.Is(err, ErrNotFound) {
		out.SkipWaitSeconds = DefaultSkipWaitSeconds
	} else {
		return out, err
	}
	return out, nil
}

// PutDNSSettings stores all three values.
func (s *SQLite) PutDNSSettings(ctx context.Context, v DNSSettings) error {
	if err := s.SetSetting(ctx, SettingDoHServer, v.Server); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, SettingDoHRetries, strconv.Itoa(v.Retries)); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, SettingDoHSkip, strconv.FormatBool(v.Skip)); err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingDoHSkipWait, strconv.Itoa(v.SkipWaitSeconds))
}
