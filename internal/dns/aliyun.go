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
	"strconv"
	"strings"
	"time"

	"github.com/mrhaoxx/certcenter/internal/cloudsign"
)

const (
	aliyunEndpoint   = "https://alidns.aliyuncs.com"
	aliyunAPIVersion = "2015-01-09"
	aliyunPageSize   = 100
)

// aliyun talks to AliDNS. domain is the zone apex managed there; there is
// no zone discovery, so the record name must fall inside it (recordRR).
type aliyun struct {
	keyID     string
	keySecret string
	domain    string
	endpoint  string

	// Injected so tests can pin the signature's timestamp and nonce.
	now   func() time.Time
	nonce func() string
}

type aliyunConfig struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	Domain          string `json:"domain"`
}

func newAliyun(configJSON string) (Provider, error) {
	var cfg aliyunConfig
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, err
	}
	if err := requireFields(map[string]string{
		"access_key_id":     cfg.AccessKeyID,
		"access_key_secret": cfg.AccessKeySecret,
		"domain":            cfg.Domain,
	}); err != nil {
		return nil, err
	}
	return &aliyun{
		keyID:     cfg.AccessKeyID,
		keySecret: cfg.AccessKeySecret,
		domain:    strings.TrimSuffix(cfg.Domain, "."),
		endpoint:  aliyunEndpoint,
		now:       time.Now,
		nonce:     cloudsign.RandomNonce,
	}, nil
}

// recordRR converts a fully-qualified record name into AliDNS's RR (the
// name relative to the zone apex).
//
// A name outside the configured zone is an error. The Rust implementation
// silently used the whole FQDN as the RR, which created a record literally
// named "_acme-challenge.other.com" inside the configured zone and left
// the challenge failing for no visible reason.
func (a *aliyun) recordRR(fqdn string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == a.domain {
		return "@", nil
	}
	suffix := "." + a.domain
	if !strings.HasSuffix(fqdn, suffix) {
		return "", fmt.Errorf("record %q is not inside the configured zone %q", fqdn, a.domain)
	}
	return strings.TrimSuffix(fqdn, suffix), nil
}

// CanHandle reports whether the name falls inside the configured zone.
// AliDNS has no zone discovery, so this is a local check and cannot fail.
func (a *aliyun) CanHandle(_ context.Context, fqdn string) (bool, error) {
	_, err := a.recordRR(fqdn)
	return err == nil, nil
}

// aliyunError is the error shape AliDNS returns. A Code in the body means
// failure even on a 2xx status.
type aliyunError struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestID string `json:"RequestId"`
}

// call signs and sends one RPC action, returning the raw JSON response.
func (a *aliyun) call(ctx context.Context, action string, params map[string]string) ([]byte, error) {
	host := a.endpoint
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	host = strings.TrimSuffix(host, "/")

	req := cloudsign.ACS3Request{
		AccessKeyID:     a.keyID,
		AccessKeySecret: a.keySecret,
		Host:            host,
		Action:          action,
		Version:         aliyunAPIVersion,
		Date:            a.now().UTC().Format("2006-01-02T15:04:05Z"),
		Nonce:           a.nonce(),
		Params:          params,
	}
	_, query, headers := req.Sign()

	// The URL must carry byte-for-byte the query string that was signed,
	// so it is concatenated rather than rebuilt with url.Values.Encode()
	// (which encodes a space as '+' and breaks the signature).
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/?"+query, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Host = host

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("aliyun %s: %w", action, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var apiErr aliyunError
	_ = json.Unmarshal(raw, &apiErr) // best effort; a success body has no Code
	if apiErr.Code != "" {
		return nil, fmt.Errorf("aliyun %s: %s - %s", action, apiErr.Code, apiErr.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("aliyun %s: HTTP %d: %s", action, resp.StatusCode, truncate(string(raw), 500))
	}
	return raw, nil
}

func (a *aliyun) AddTXT(ctx context.Context, name, value string) error {
	rr, err := a.recordRR(name)
	if err != nil {
		return err
	}
	_, err = a.call(ctx, "AddDomainRecord", map[string]string{
		"DomainName": a.domain,
		"RR":         rr,
		"Type":       "TXT",
		"Value":      value,
	})
	if err != nil {
		// A duplicate means a record with this exact RR, type and value
		// already exists — the state we wanted. Treat it as success and,
		// crucially, do NOT delete same-RR records to retry: that would
		// destroy the sibling challenge when a certificate covers both the
		// apex and its wildcard.
		if strings.Contains(err.Error(), "DomainRecordDuplicate") {
			return nil
		}
		return err
	}
	return nil
}

type aliyunRecord struct {
	RecordID string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
}

type aliyunDescribeResponse struct {
	TotalCount    int `json:"TotalCount"`
	PageNumber    int `json:"PageNumber"`
	PageSize      int `json:"PageSize"`
	DomainRecords struct {
		Record []aliyunRecord `json:"Record"`
	} `json:"DomainRecords"`
}

func (a *aliyun) RemoveTXT(ctx context.Context, name, value string) error {
	rr, err := a.recordRR(name)
	if err != nil {
		return err
	}

	// Paginate: AliDNS defaults to 20 records per page, and the Rust
	// implementation read only the first page, so a busy zone left
	// challenge records behind.
	//
	// Termination counts the records actually returned rather than
	// multiplying our requested PageSize by the page number. The server may
	// cap the page size below what we ask for, and the multiply-out form
	// then overshoots TotalCount and stops early — silently skipping
	// records that still need deleting.
	fetched := 0
	for page := 1; ; page++ {
		raw, err := a.call(ctx, "DescribeDomainRecords", map[string]string{
			"DomainName":  a.domain,
			"RRKeyWord":   rr,
			"TypeKeyWord": "TXT",
			"PageNumber":  strconv.Itoa(page),
			"PageSize":    strconv.Itoa(aliyunPageSize),
		})
		if err != nil {
			return err
		}
		var listed aliyunDescribeResponse
		if err := json.Unmarshal(raw, &listed); err != nil {
			return fmt.Errorf("aliyun: malformed record list: %w", err)
		}

		for _, rec := range listed.DomainRecords.Record {
			// Exact match only — RRKeyWord is a keyword filter, so the
			// server may return neighbours.
			if rec.Type != "TXT" || rec.RR != rr || rec.Value != value {
				continue
			}
			if _, err := a.call(ctx, "DeleteDomainRecord", map[string]string{
				"RecordId": rec.RecordID,
			}); err != nil {
				return err
			}
		}

		fetched += len(listed.DomainRecords.Record)
		if len(listed.DomainRecords.Record) == 0 || fetched >= listed.TotalCount {
			break
		}
	}
	// Absent is the desired state, so a missing record is success.
	return nil
}
