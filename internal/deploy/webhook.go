// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
)

// webhook POSTs the certificate to a URL. There is no built-in signature —
// authentication is whatever token the operator puts in Headers.
type webhook struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

func newWebhook(configJSON string) (Target, error) {
	var w webhook
	if err := decodeConfig(configJSON, &w); err != nil {
		return nil, err
	}
	if w.URL == "" {
		return nil, fmt.Errorf("webhook target requires a url")
	}
	return &w, nil
}

// webhookPayload is the POST body. The field names are a data contract:
// existing receivers parse exactly these.
type webhookPayload struct {
	Domain      string `json:"domain"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	Chain       string `json:"chain"`
}

func (w *webhook) Deploy(ctx context.Context, cert *CertificateData) ([]Event, error) {
	var events []Event

	names := make([]string, 0, len(w.Headers))
	for k := range w.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	events = append(events, Event{
		Type: "webhook_send", Level: LevelInfo,
		Message: fmt.Sprintf("POST %s", w.URL),
		Detail:  fmt.Sprintf("domain=%s, headers=%s", cert.Domain, strings.Join(names, ",")),
	})

	body, err := json.Marshal(webhookPayload{
		Domain:      cert.Domain,
		Certificate: cert.CertPEM,
		PrivateKey:  cert.KeyPEM,
		Chain:       cert.ChainPEM,
	})
	if err != nil {
		return events, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return events, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Custom headers are applied last so they can override the default.
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		events = append(events, Event{
			Type: "webhook_error", Level: LevelError,
			Message: fmt.Sprintf("Webhook request failed: %v", err),
		})
		return events, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
		events = append(events, Event{
			Type: "webhook_response", Level: LevelError,
			Message: fmt.Sprintf("Webhook returned %d", resp.StatusCode),
			Detail:  truncate(string(raw), 1000),
		})
		return events, err
	}
	events = append(events, Event{
		Type: "webhook_response", Level: LevelSuccess,
		Message: fmt.Sprintf("Webhook returned %d", resp.StatusCode),
	})
	return events, nil
}
