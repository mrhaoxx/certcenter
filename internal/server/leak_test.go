// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/secret"
)

// These are the exact strings a leak would surface. They are distinctive
// so a substring match cannot pass by accident.
const (
	leakCFToken     = "cfat_LEAKCANARY_cloudflare"
	leakAliSecret   = "LEAKCANARY_aliyun_secret"
	leakSSHKey      = "-----BEGIN OPENSSH PRIVATE KEY-----LEAKCANARY"
	leakSSHPassword = "LEAKCANARY_ssh_password"
	leakWebhookAuth = "Bearer LEAKCANARY_webhook"
)

// TestNoEndpointLeaksSecrets walks every endpoint that can return a
// provider or a target and asserts no stored credential appears.
//
// The API used to hand back dns_providers.config and deploy_targets.config
// verbatim — a Cloudflare API token and SSH private keys went to the
// browser on every page load, while the ACME account key and certificate
// private key were correctly withheld. This test exists so a new endpoint
// cannot quietly reopen that.
func TestNoEndpointLeaksSecrets(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	providerID, err := srv.DB.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "cf", Kind: "cloudflare",
		Config: `{"api_token":"` + leakCFToken + `","zone_id":"z1"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.DB.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "ali", Kind: "aliyun",
		Config: `{"access_key_id":"LTAI","access_key_secret":"` + leakAliSecret + `","domain":"e.com"}`,
	}); err != nil {
		t.Fatal(err)
	}
	targetID, err := srv.DB.CreateDeployTarget(ctx, db.DeployTarget{
		Name: "web", Kind: "ssh",
		Config: `{"steps":[{"type":"ssh_connect","config":{"host":"h","private_key":"` +
			leakSSHKey + `","password":"` + leakSSHPassword + `"}}]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.DB.CreateDeployTarget(ctx, db.DeployTarget{
		Name: "hook", Kind: "webhook",
		Config: `{"url":"https://h/x","headers":{"Authorization":"` + leakWebhookAuth + `"}}`,
	}); err != nil {
		t.Fatal(err)
	}

	canaries := []string{leakCFToken, leakAliSecret, leakSSHKey, leakSSHPassword, leakWebhookAuth}

	paths := []struct{ method, path, body string }{
		{http.MethodGet, "/api/dns-providers", ""},
		{http.MethodGet, "/api/deploy-targets", ""},
		{http.MethodGet, "/api/certificates", ""},
		{http.MethodGet, "/api/dashboard", ""},
		{http.MethodGet, "/api/logs", ""},
		{http.MethodPatch, "/api/dns-providers/" + itoa64(providerID), `{"name":"renamed"}`},
		{http.MethodPatch, "/api/deploy-targets/" + itoa64(targetID), `{"name":"renamed"}`},
	}

	for _, p := range paths {
		t.Run(p.method+" "+p.path, func(t *testing.T) {
			rec := authed(t, srv, p.method, p.path, p.body)
			body := rec.Body.String()
			for _, canary := range canaries {
				if strings.Contains(body, canary) {
					t.Errorf("response leaks a stored credential (%s):\n%s", canary, body)
				}
			}
		})
	}
}

// TestRenameKeepsTheStoredSecret pairs with the redaction: masking is only
// safe if editing an unrelated field does not wipe the credential the form
// never displayed.
func TestRenameKeepsTheStoredSecret(t *testing.T) {
	srv := newTestServer(t)
	ctx := context.Background()

	id, err := srv.DB.CreateDNSProvider(ctx, db.DNSProvider{
		Name: "cf", Kind: "cloudflare",
		Config: `{"api_token":"` + leakCFToken + `","zone_id":"z1"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	// What the browser would send back: the mask it was shown, plus an edit.
	body := `{"name":"renamed","config":"{\"api_token\":\"` + secret.Value +
		`\",\"zone_id\":\"z2\"}"}`
	rec := authed(t, srv, http.MethodPatch, "/api/dns-providers/"+itoa64(id), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}

	stored, err := srv.DB.GetDNSProvider(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored.Config, leakCFToken) {
		t.Errorf("the stored token was overwritten by the mask: %s", stored.Config)
	}
	if !strings.Contains(stored.Config, "z2") {
		t.Errorf("the edited zone_id was not saved: %s", stored.Config)
	}
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
