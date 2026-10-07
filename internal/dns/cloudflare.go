// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	cloudflareAPI = "https://api.cloudflare.com/client/v4"
	// cloudflareTXTTTL keeps the challenge record short-lived so a stale
	// value cannot linger past a failed issuance.
	cloudflareTXTTTL = 120
)

// cloudflare talks to the Cloudflare v4 DNS API with a scoped API token.
//
// zoneID is optional. Given one, the provider serves exactly that zone and
// the token only needs Zone:DNS:Edit. Left empty, the zone is discovered
// from the record name, which additionally requires Zone:Zone:Read —
// listing zones is a broader permission than editing records in one. Both
// modes exist because neither is right for everyone: a token narrowed to a
// single zone cannot list zones, and an operator with many zones should
// not have to paste an ID per zone.
type cloudflare struct {
	token   string
	zoneID  string
	baseURL string

	// discovered caches zone lookups for the life of the provider, so an
	// issuance covering several names in one zone resolves it once.
	mu         sync.Mutex
	discovered map[string]string
}

type cloudflareConfig struct {
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id"`
}

func newCloudflare(configJSON string) (Provider, error) {
	var cfg cloudflareConfig
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, err
	}
	// zone_id is deliberately absent here: empty means "discover it".
	if err := requireFields(map[string]string{"api_token": cfg.APIToken}); err != nil {
		return nil, err
	}
	return &cloudflare{
		token:      cfg.APIToken,
		zoneID:     cfg.ZoneID,
		baseURL:    cloudflareAPI,
		discovered: map[string]string{},
	}, nil
}

// zoneFor resolves the zone that owns a record name.
//
// It walks the name's parent labels — _acme-challenge.a.example.com →
// a.example.com → example.com — and asks Cloudflare for each until one
// matches. That is the same approach lego and certbot take, and it costs
// at most a couple of requests because a zone is usually the registrable
// domain. The final label is skipped: a TLD is never a zone anyone owns.
// CanHandle reports whether a zone covering the name exists in this
// account. With zone_id pinned the answer is yes without asking, since the
// operator has said which zone to use.
func (c *cloudflare) CanHandle(ctx context.Context, fqdn string) (bool, error) {
	if c.zoneID != "" {
		return true, nil
	}
	zone, err := c.zoneFor(ctx, fqdn)
	if err != nil {
		// zoneFor reports "no zone matched" and "the lookup failed" as the
		// same kind of value, so the distinction is drawn here: a missing
		// zone is a definite no, anything else is unanswerable.
		if errors.Is(err, errNoZone) {
			return false, nil
		}
		return false, err
	}
	return zone != "", nil
}

// errNoZone distinguishes "this account holds no zone for that name" from
// "the lookup could not be performed". CanHandle turns the first into a
// definite no and passes the second up, because a provider whose API is
// down must not look like one that simply does not own the domain.
var errNoZone = errors.New("no Cloudflare zone found")

func (c *cloudflare) zoneFor(ctx context.Context, name string) (string, error) {
	if c.zoneID != "" {
		return c.zoneID, nil
	}

	c.mu.Lock()
	if id, ok := c.discovered[name]; ok {
		c.mu.Unlock()
		return id, nil
	}
	c.mu.Unlock()

	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	var lastErr error
	for i := 0; i+1 < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		id, err := c.lookupZone(ctx, candidate)
		if err != nil {
			// A permission failure is worth surfacing rather than being
			// buried under "no zone found".
			lastErr = err
			break
		}
		if id == "" {
			continue
		}
		c.mu.Lock()
		c.discovered[name] = id
		c.mu.Unlock()
		return id, nil
	}

	if lastErr != nil {
		return "", fmt.Errorf("looking up the Cloudflare zone for %q: %w "+
			"(zone discovery needs a token with Zone:Read; alternatively set zone_id)", name, lastErr)
	}
	return "", fmt.Errorf("%w for %q; check the token covers this domain, "+
		"or set zone_id explicitly", errNoZone, name)
}

// lookupZone returns the zone id for an exact zone name, or "" if the
// token can see no such zone.
func (c *cloudflare) lookupZone(ctx context.Context, zoneName string) (string, error) {
	q := url.Values{}
	q.Set("name", zoneName)
	env, err := c.do(ctx, http.MethodGet, "/zones?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(env.Result, &zones); err != nil {
		return "", fmt.Errorf("malformed zone list: %w", err)
	}
	var matches []string
	for _, z := range zones {
		// Match exactly: the name filter supports contains/startswith
		// operators, so a loose server-side match must not be trusted.
		if z.Name == zoneName {
			matches = append(matches, z.ID)
		}
	}
	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return matches[0], nil
	default:
		// A token spanning several accounts, or a domain mid-transfer, can
		// surface the same name twice. Picking one would write the
		// challenge record into the wrong zone and leave validation failing
		// for no visible reason, so refuse and make the operator decide.
		return "", fmt.Errorf("zone %q is ambiguous: %d zones match (%s); "+
			"set zone_id to choose one", zoneName, len(matches), strings.Join(matches, ", "))
	}
}

// cloudflareEnvelope is the wrapper around every v4 response. success must
// be checked: the API can answer 200 with success:false, which the Rust
// implementation treated as a successful write.
type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (e cloudflareEnvelope) err() error {
	if e.Success {
		return nil
	}
	if len(e.Errors) == 0 {
		return fmt.Errorf("cloudflare API reported failure with no error detail")
	}
	msgs := make([]string, 0, len(e.Errors))
	for _, x := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d %s", x.Code, x.Message))
	}
	return fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
}

// do performs a request and decodes the envelope, failing on both a
// non-2xx status and success:false.
func (c *cloudflare) do(ctx context.Context, method, path string, body any) (*cloudflareEnvelope, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var env cloudflareEnvelope
	if jsonErr := json.Unmarshal(raw, &env); jsonErr != nil {
		// A non-JSON body on an error status is more useful verbatim.
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("cloudflare %s %s: HTTP %d: %s",
				method, path, resp.StatusCode, truncate(string(raw), 500))
		}
		return nil, fmt.Errorf("cloudflare %s %s: malformed response: %w", method, path, jsonErr)
	}
	if err := env.err(); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cloudflare %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return &env, nil
}

func (c *cloudflare) AddTXT(ctx context.Context, name, value string) error {
	zone, err := c.zoneFor(ctx, name)
	if err != nil {
		return err
	}
	// Purely additive — see the Provider doc comment on why same-name
	// records must not be replaced.
	_, err = c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     cloudflareTXTTTL,
	})
	return err
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *cloudflare) RemoveTXT(ctx context.Context, name, value string) error {
	zone, err := c.zoneFor(ctx, name)
	if err != nil {
		return err
	}
	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name", name)
	env, err := c.do(ctx, http.MethodGet,
		"/zones/"+zone+"/dns_records?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	var records []cloudflareRecord
	if err := json.Unmarshal(env.Result, &records); err != nil {
		return fmt.Errorf("cloudflare: malformed record list: %w", err)
	}

	for _, rec := range records {
		// Match exactly on our own name and value. The server-side name
		// filter has modifiers (name.exact, name.contains) whose semantics
		// we must not depend on; a loose match would delete a sibling
		// challenge's record.
		if rec.Type != "TXT" || rec.Name != name || rec.Content != value {
			continue
		}
		if _, err := c.do(ctx, http.MethodDelete,
			"/zones/"+zone+"/dns_records/"+url.PathEscape(rec.ID), nil); err != nil {
			return err
		}
	}
	// No match is success: cleanup runs again after a retry, and the
	// desired state (record absent) already holds.
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
