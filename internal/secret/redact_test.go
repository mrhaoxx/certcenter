// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactHidesProviderCredentials(t *testing.T) {
	tests := []struct {
		name, config, mustNotContain string
	}{
		{"cloudflare token", `{"api_token":"cfat_secret","zone_id":"z1"}`, "cfat_secret"},
		{"aliyun secret", `{"access_key_id":"LTAI","access_key_secret":"shhh","domain":"e.com"}`, "shhh"},
		{"webhook token header", `{"url":"https://h/x","headers":{"Authorization":"Bearer tok"}}`, "Bearer tok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.config)
			if strings.Contains(got, tt.mustNotContain) {
				t.Errorf("redacted config still contains the secret: %s", got)
			}
			if !strings.Contains(got, Value) {
				t.Errorf("nothing was masked: %s", got)
			}
		})
	}
}

func TestRedactKeepsNonSecrets(t *testing.T) {
	// Masking everything would make the edit form useless.
	got := Redact(`{"api_token":"secret","zone_id":"zone123"}`)
	if !strings.Contains(got, "zone123") {
		t.Errorf("zone_id was masked too: %s", got)
	}
}

func TestRedactReachesIntoSSHPipelineSteps(t *testing.T) {
	// An SSH target keeps its private key inside a step, not at the top
	// level. A per-kind list of top-level fields would have missed it and
	// shipped the key to the browser.
	config := `{"steps":[
	  {"type":"ssh_connect","config":{"host":"h","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----","password":"pw"}},
	  {"type":"run_command","config":{"command":"nginx -s reload"}}
	]}`
	got := Redact(config)
	for _, secret := range []string{"BEGIN OPENSSH PRIVATE KEY", `"pw"`} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q survived redaction: %s", secret, got)
		}
	}
	if !strings.Contains(got, "nginx -s reload") {
		t.Errorf("a non-secret command was masked: %s", got)
	}
	if !strings.Contains(got, `"host":"h"`) {
		t.Errorf("host was masked: %s", got)
	}
}

func TestRedactUnparseableConfigRevealsNothing(t *testing.T) {
	// If it cannot be understood it cannot be safely masked.
	if got := Redact(`{"api_token":"secret"`); strings.Contains(got, "secret") {
		t.Errorf("malformed config leaked: %s", got)
	}
}

func TestRedactLeavesEmptyStringsAlone(t *testing.T) {
	// Masking an unset field would tell the operator a credential exists
	// when none does.
	got := Redact(`{"api_token":"","zone_id":"z"}`)
	if strings.Contains(got, Value) {
		t.Errorf("an empty secret was masked: %s", got)
	}
}

func TestRestorePutsStoredSecretsBack(t *testing.T) {
	stored := `{"api_token":"cfat_real","zone_id":"old"}`
	incoming := `{"api_token":"` + Value + `","zone_id":"new"}`

	got := Restore(incoming, stored)
	var m map[string]any
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatal(err)
	}
	if m["api_token"] != "cfat_real" {
		t.Errorf("api_token = %v, want the stored secret restored", m["api_token"])
	}
	if m["zone_id"] != "new" {
		t.Errorf("zone_id = %v, want the edited value kept", m["zone_id"])
	}
}

func TestRestoreAcceptsAReplacedSecret(t *testing.T) {
	// Typing a new credential must replace the old one, not be treated as
	// an unchanged mask.
	got := Restore(`{"api_token":"cfat_new"}`, `{"api_token":"cfat_old"}`)
	if !strings.Contains(got, "cfat_new") {
		t.Errorf("a freshly typed secret was discarded: %s", got)
	}
}

func TestRestoreReachesIntoSteps(t *testing.T) {
	stored := `{"steps":[{"type":"ssh_connect","config":{"host":"h","private_key":"KEYMATERIAL"}}]}`
	incoming := `{"steps":[{"type":"ssh_connect","config":{"host":"h2","private_key":"` + Value + `"}}]}`

	got := Restore(incoming, stored)
	if !strings.Contains(got, "KEYMATERIAL") {
		t.Errorf("the nested private key was not restored: %s", got)
	}
	if !strings.Contains(got, "h2") {
		t.Errorf("the edited host was lost: %s", got)
	}
}

func TestRestoreWithNoPriorValueLeavesTheMask(t *testing.T) {
	// Nothing to restore from: the mask travels on and the provider's own
	// validation rejects it, rather than silently storing a literal mask
	// that would fail much later against the real API.
	got := Restore(`{"api_token":"`+Value+`"}`, `{}`)
	if !strings.Contains(got, Value) {
		t.Errorf("expected the mask to survive with no stored value: %s", got)
	}
}

func TestRedactRestoreRoundTrip(t *testing.T) {
	// The realistic flow: read, edit one visible field, write back.
	stored := `{"access_key_id":"LTAI","access_key_secret":"shhh","domain":"a.com"}`
	shown := Redact(stored)
	if strings.Contains(shown, "shhh") {
		t.Fatalf("the secret reached the client: %s", shown)
	}
	edited := strings.Replace(shown, `"a.com"`, `"b.com"`, 1)
	final := Restore(edited, stored)

	var m map[string]any
	if err := json.Unmarshal([]byte(final), &m); err != nil {
		t.Fatal(err)
	}
	if m["access_key_secret"] != "shhh" {
		t.Errorf("secret = %v, want it preserved through the round trip", m["access_key_secret"])
	}
	if m["domain"] != "b.com" {
		t.Errorf("domain = %v, want the edit applied", m["domain"])
	}
}
