// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MaxCNAMEDepth bounds the chain walk. Delegation is normally one hop;
// more than a handful means a loop or a mistake, and following it forever
// would hang an issuance.
const MaxCNAMEDepth = 10

// dohCNAMEType is the DNS type number for CNAME in a dns-json answer.
const dohCNAMEType = 5

// ResolveChallengeTarget follows any CNAME chain from the challenge record
// name and returns where the TXT actually has to be written.
//
// This is what makes delegated validation work without configuration. An
// operator who cannot get DNS API credentials for example.com creates one
// CNAME by hand —
//
//	_acme-challenge.example.com. CNAME _acme-challenge.delegated.net.
//
// — and from then on the TXT is written in the zone they do control. The
// CA follows the same CNAME as ordinary resolution, so it needs to know
// nothing about the arrangement.
//
// acme.sh makes the operator declare this per certificate with
// --challenge-alias; lego resolves it instead, and so does this. There is
// nothing to configure and nothing to keep in sync.
//
// A lookup failure returns the original name: a resolver that is down must
// not stop an issuance that would otherwise have worked unaliased.
func (v *Verifier) ResolveChallengeTarget(ctx context.Context, name string) (string, error) {
	current := name
	for depth := 0; depth < MaxCNAMEDepth; depth++ {
		target, err := v.lookupCNAME(ctx, current)
		if err != nil {
			return name, err
		}
		if target == "" || strings.EqualFold(target, current) {
			return current, nil
		}
		current = target
	}
	return "", fmt.Errorf("the CNAME chain from %q is longer than %d hops; it is probably a loop",
		name, MaxCNAMEDepth)
}

// lookupCNAME returns the CNAME target for a name, or "" if there is none.
func (v *Verifier) lookupCNAME(ctx context.Context, name string) (string, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", "CNAME")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Server+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := v.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("CNAME lookup failed: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	var answer struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return "", fmt.Errorf("CNAME lookup returned malformed JSON: %w", err)
	}
	// NXDOMAIN simply means no delegation exists.
	if answer.Status == dohNXDOMAIN {
		return "", nil
	}
	for _, a := range answer.Answer {
		if a.Type == dohCNAMEType && a.Data != "" {
			// dns-json returns the target with a trailing dot.
			return strings.TrimSuffix(a.Data, "."), nil
		}
	}
	return "", nil
}
