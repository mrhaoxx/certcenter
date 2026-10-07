// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// http_request and verify_ssl run from the CertCenter host, not over the
// SSH session — they exist to poke an external API or to confirm the new
// certificate is actually being served.

func stepHTTPRequest(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	cfg := struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Body    string            `json:"body"`
		Headers map[string]string `json:"headers"`
		// Insecure skips certificate verification. A reload endpoint often
		// sits on the very host being re-certified, presenting the old or
		// a self-signed certificate at the moment this runs — verifying it
		// would fail exactly when the step is most needed.
		Insecure bool `json:"insecure"`
		// ExpectStatus fails the step unless the response carries this
		// code. Zero keeps the default: any status is reported, none is
		// fatal, because an endpoint may answer 404 or 409 harmlessly.
		ExpectStatus int `json:"expect_status"`
	}{Method: http.MethodGet}
	json.Unmarshal(raw, &cfg)

	method := strings.ToUpper(cfg.Method)
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodGet:
	default:
		method = http.MethodGet
	}

	url := st.expand(cfg.URL)
	var body io.Reader
	if cfg.Body != "" {
		body = strings.NewReader(st.expand(cfg.Body))
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if cfg.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, st.expand(v))
	}

	detail := ""
	if cfg.Insecure {
		detail = "Certificate verification is disabled for this request."
	}
	st.emit(Event{Type: StepHTTPRequest, Level: LevelInfo,
		Message: fmt.Sprintf("%s %s", method, url), Detail: detail})

	client := httpClient
	if cfg.Insecure {
		client = insecureHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		// A transport failure is fatal: the operator asked us to call
		// something and we could not.
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()
	raw2, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Non-2xx is informational, matching run_command: the endpoint may
	// legitimately answer 404 or 409 without invalidating the deployment.
	level := LevelSuccess
	message := fmt.Sprintf("HTTP %s → %d", method, resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		level = LevelInfo
		message = fmt.Sprintf("HTTP %s returned %d", method, resp.StatusCode)
	}
	st.emit(Event{Type: StepHTTPRequest, Level: level, Message: message,
		Detail: truncate(string(raw2), 500)})

	// An explicit expectation turns the reload into something that can
	// fail: "I asked nginx to reload and it answered 500" should stop the
	// pipeline rather than be filed as a note.
	if cfg.ExpectStatus != 0 && resp.StatusCode != cfg.ExpectStatus {
		return fmt.Errorf("%s %s returned %d, expected %d",
			method, url, resp.StatusCode, cfg.ExpectStatus)
	}
	return nil
}

func stepVerifySSL(ctx context.Context, st *pipelineState, raw json.RawMessage) error {
	cfg := struct {
		Domain      string `json:"domain"`
		Port        int    `json:"port"`
		TimeoutSecs int    `json:"timeout_secs"`
	}{Domain: "{{domain}}", Port: 443, TimeoutSecs: 10}
	json.Unmarshal(raw, &cfg)
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 10
	}

	domain := st.expand(cfg.Domain)
	addr := net.JoinHostPort(domain, strconv.Itoa(cfg.Port))
	timeout := time.Duration(cfg.TimeoutSecs) * time.Second

	st.emit(Event{Type: StepVerifySSL, Level: LevelInfo,
		Message: fmt.Sprintf("Verifying TLS on %s", addr)})

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// DNS or TCP failure is fatal: the host is unreachable, which is a
		// real problem rather than a certificate that has not propagated.
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: domain})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		// A handshake failure is reported but not fatal: a load balancer
		// may still be rolling the new certificate out.
		st.emit(Event{Type: StepVerifySSL, Level: LevelError,
			Message: fmt.Sprintf("TLS handshake with %s failed", addr), Detail: err.Error()})
		return nil
	}
	state := tlsConn.ConnectionState()

	detail := ""
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		detail = fmt.Sprintf("subject=%s\nnot_after=%s\nserial=%X",
			leaf.Subject, leaf.NotAfter.UTC().Format(time.RFC3339), leaf.SerialNumber)
	}
	st.emit(Event{Type: StepVerifySSL, Level: LevelSuccess,
		Message: fmt.Sprintf("TLS verified for %s", addr), Detail: detail})
	return nil
}

// insecureHTTPClient is used only by steps that explicitly ask for it. It
// is a package-level value so the transport and its connection pool are
// shared rather than rebuilt per request.
var insecureHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		//nolint:gosec // deliberate: see the Insecure field's documentation
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}
