// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"testing"
)

func TestDNSSettingsSkipWaitDefaultsForOlderRows(t *testing.T) {
	// An instance that saved DNS settings before skip_wait existed has the
	// other three keys but not this one. Reading zero there would quietly
	// opt it out of the wait that a fresh install receives.
	s := NewTestDB(t)
	ctx := context.Background()

	for k, v := range map[string]string{
		SettingDoHServer:  "https://dns.example/q",
		SettingDoHRetries: "5",
		SettingDoHSkip:    "true",
	} {
		if err := s.SetSetting(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.GetDNSSettings(ctx, DNSSettings{})
	if err != nil {
		t.Fatal(err)
	}
	if got.SkipWaitSeconds != DefaultSkipWaitSeconds {
		t.Errorf("SkipWaitSeconds = %d, want the %d default for a row that predates the field",
			got.SkipWaitSeconds, DefaultSkipWaitSeconds)
	}
	if got.Server != "https://dns.example/q" || got.Retries != 5 || !got.Skip {
		t.Errorf("the other stored values were disturbed: %+v", got)
	}
}

func TestDNSSettingsExplicitZeroIsKept(t *testing.T) {
	// Zero is a legitimate choice — do not treat it as unset.
	s := NewTestDB(t)
	ctx := context.Background()
	if err := s.PutDNSSettings(ctx, DNSSettings{
		Server: "https://d/q", Retries: 3, SkipWaitSeconds: 0,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDNSSettings(ctx, DNSSettings{SkipWaitSeconds: DefaultSkipWaitSeconds})
	if err != nil {
		t.Fatal(err)
	}
	if got.SkipWaitSeconds != 0 {
		t.Errorf("SkipWaitSeconds = %d, want the explicit 0 preserved", got.SkipWaitSeconds)
	}
}
