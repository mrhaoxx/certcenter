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
	"strings"
	"time"

	"github.com/mrhaoxx/certcenter/internal/cloudsign"
)

// Both CDN targets were stubs in the Rust implementation: they logged
// "not yet implemented", discarded the credentials and returned an error.
// They are implemented for real here.

// ── Aliyun CDN ─────────────────────────────────────────────────────────

const (
	aliyunCDNEndpoint = "https://cdn.aliyuncs.com"
	aliyunCDNVersion  = "2018-05-10"
)

type aliyunCDN struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	CDNDomain       string `json:"cdn_domain"`

	endpoint string
	now      func() time.Time
	nonce    func() string
}

func newAliyunCDN(configJSON string) (Target, error) {
	var c aliyunCDN
	if err := decodeConfig(configJSON, &c); err != nil {
		return nil, err
	}
	if c.AccessKeyID == "" || c.AccessKeySecret == "" || c.CDNDomain == "" {
		return nil, fmt.Errorf("aliyun_cdn requires access_key_id, access_key_secret and cdn_domain")
	}
	c.endpoint = aliyunCDNEndpoint
	c.now = time.Now
	c.nonce = cloudsign.RandomNonce
	return &c, nil
}

func (a *aliyunCDN) Deploy(ctx context.Context, cert *CertificateData) ([]Event, error) {
	var events []Event
	events = append(events, Event{
		Type: "aliyun_cdn", Level: LevelInfo,
		Message: fmt.Sprintf("Installing the certificate on Aliyun CDN domain %s", a.CDNDomain),
		Detail:  fmt.Sprintf("domain=%s", cert.Domain),
	})

	host := strings.TrimPrefix(strings.TrimPrefix(a.endpoint, "https://"), "http://")
	req := cloudsign.ACS3Request{
		AccessKeyID:     a.AccessKeyID,
		AccessKeySecret: a.AccessKeySecret,
		Host:            host,
		Action:          "SetCdnDomainSSLCertificate",
		Version:         aliyunCDNVersion,
		Date:            a.now().UTC().Format("2006-01-02T15:04:05Z"),
		Nonce:           a.nonce(),
		Params: map[string]string{
			"DomainName":  a.CDNDomain,
			"CertType":    "upload",
			"SSLProtocol": "on",
			"CertName":    fmt.Sprintf("certcenter-%s-%d", cert.Domain, a.now().UTC().Unix()),
			// The CDN wants the full chain, which is why cert and chain are
			// recombined here rather than stored that way.
			"SSLPub": cert.FullChainPEM(),
			"SSLPri": cert.KeyPEM,
		},
	}
	_, query, headers := req.Sign()

	// The transmitted query string must be byte-identical to the signed one.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/?"+query, nil)
	if err != nil {
		return events, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Host = host

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		events = append(events, Event{Type: "aliyun_cdn", Level: LevelError,
			Message: "Aliyun CDN request failed", Detail: err.Error()})
		return events, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var apiErr struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	_ = json.Unmarshal(raw, &apiErr)
	if apiErr.Code != "" {
		err := fmt.Errorf("aliyun CDN: %s - %s", apiErr.Code, apiErr.Message)
		events = append(events, Event{Type: "aliyun_cdn", Level: LevelError,
			Message: "Aliyun CDN rejected the certificate", Detail: truncate(string(raw), 1000)})
		return events, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("aliyun CDN: HTTP %d", resp.StatusCode)
		events = append(events, Event{Type: "aliyun_cdn", Level: LevelError,
			Message: err.Error(), Detail: truncate(string(raw), 1000)})
		return events, err
	}

	events = append(events, Event{Type: "aliyun_cdn", Level: LevelSuccess,
		Message: fmt.Sprintf("Certificate installed on %s", a.CDNDomain)})
	return events, nil
}

// ── Tencent CDN ────────────────────────────────────────────────────────

const (
	tencentCDNHost    = "cdn.tencentcloudapi.com"
	tencentCDNVersion = "2018-06-06"
	tencentCDNService = "cdn"
)

type tencentCDN struct {
	SecretID  string `json:"secret_id"`
	SecretKey string `json:"secret_key"`
	CDNDomain string `json:"cdn_domain"`
	Region    string `json:"region"`

	host string
	url  string
	now  func() time.Time
}

func newTencentCDN(configJSON string) (Target, error) {
	var c tencentCDN
	if err := decodeConfig(configJSON, &c); err != nil {
		return nil, err
	}
	if c.SecretID == "" || c.SecretKey == "" || c.CDNDomain == "" {
		return nil, fmt.Errorf("tencent_cdn requires secret_id, secret_key and cdn_domain")
	}
	c.host = tencentCDNHost
	c.url = "https://" + tencentCDNHost
	c.now = time.Now
	return &c, nil
}

func (t *tencentCDN) Deploy(ctx context.Context, cert *CertificateData) ([]Event, error) {
	var events []Event
	events = append(events, Event{
		Type: "tencent_cdn", Level: LevelInfo,
		Message: fmt.Sprintf("Installing the certificate on Tencent CDN domain %s", t.CDNDomain),
		Detail:  fmt.Sprintf("domain=%s", cert.Domain),
	})

	payload, err := json.Marshal(map[string]any{
		"Domain": t.CDNDomain,
		"Https": map[string]any{
			"Switch": "on",
			"CertInfo": map[string]any{
				"Certificate": cert.FullChainPEM(),
				"PrivateKey":  cert.KeyPEM,
			},
		},
	})
	if err != nil {
		return events, err
	}

	req := cloudsign.TC3Request{
		SecretID:  t.SecretID,
		SecretKey: t.SecretKey,
		Host:      t.host,
		Service:   tencentCDNService,
		Action:    "UpdateDomainConfig",
		Version:   tencentCDNVersion,
		Region:    t.Region,
		Timestamp: t.now(),
		Payload:   string(payload),
	}
	_, headers := req.Sign()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewReader(payload))
	if err != nil {
		return events, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Host = t.host

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		events = append(events, Event{Type: "tencent_cdn", Level: LevelError,
			Message: "Tencent CDN request failed", Detail: err.Error()})
		return events, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Tencent reports API errors inside a 200 body, so the status code alone
	// is not enough.
	var body struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			RequestID string `json:"RequestId"`
		} `json:"Response"`
	}
	_ = json.Unmarshal(raw, &body)
	if body.Response.Error != nil {
		err := fmt.Errorf("tencent CDN: %s - %s",
			body.Response.Error.Code, body.Response.Error.Message)
		events = append(events, Event{Type: "tencent_cdn", Level: LevelError,
			Message: "Tencent CDN rejected the certificate", Detail: truncate(string(raw), 1000)})
		return events, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("tencent CDN: HTTP %d", resp.StatusCode)
		events = append(events, Event{Type: "tencent_cdn", Level: LevelError,
			Message: err.Error(), Detail: truncate(string(raw), 1000)})
		return events, err
	}

	events = append(events, Event{Type: "tencent_cdn", Level: LevelSuccess,
		Message: fmt.Sprintf("Certificate installed on %s", t.CDNDomain),
		Detail:  "RequestId: " + body.Response.RequestID})
	return events, nil
}
