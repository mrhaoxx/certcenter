// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package cloudsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TC3-HMAC-SHA256 is Tencent Cloud's API 3.0 request signature.
const tc3Algorithm = "TC3-HMAC-SHA256"

// TC3Request carries everything the signature covers. Unlike Aliyun's
// scheme every parameter travels in the JSON body, so Payload is signed
// rather than a query string.
type TC3Request struct {
	SecretID  string
	SecretKey string
	Host      string
	Service   string // e.g. "cdn"
	Action    string
	Version   string
	Region    string
	Timestamp time.Time
	Payload   string
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// contentType is fixed: the signature covers it, so it must match what the
// request actually sends.
const tc3ContentType = "application/json; charset=utf-8"

// CanonicalRequest builds the string whose hash the signature covers.
//
// The action header carries the lowercased action name, and the headers are
// listed in sorted order with a trailing blank line before SignedHeaders —
// this assembly is where signing implementations usually go wrong, so it is
// locked against Tencent's published example in tc3_test.go.
func (r TC3Request) CanonicalRequest() string {
	return "POST\n" +
		"/\n" +
		"\n" + // no query string; everything is in the body
		"content-type:" + tc3ContentType + "\n" +
		"host:" + r.Host + "\n" +
		"x-tc-action:" + strings.ToLower(r.Action) + "\n" +
		"\n" +
		"content-type;host;x-tc-action\n" +
		sha256Hex(r.Payload)
}

// credentialScope is "<date>/<service>/tc3_request" in UTC.
func (r TC3Request) credentialScope() string {
	return fmt.Sprintf("%s/%s/tc3_request", r.Timestamp.UTC().Format("2006-01-02"), r.Service)
}

func (r TC3Request) StringToSign() string {
	return tc3Algorithm + "\n" +
		fmt.Sprintf("%d", r.Timestamp.UTC().Unix()) + "\n" +
		r.credentialScope() + "\n" +
		sha256Hex(r.CanonicalRequest())
}

// Sign returns the Authorization header value and the other headers to send.
func (r TC3Request) Sign() (string, map[string]string) {
	// Key derivation chain, per the specification:
	//   SecretDate    = HMAC("TC3"+SecretKey, date)
	//   SecretService = HMAC(SecretDate, service)
	//   SecretSigning = HMAC(SecretService, "tc3_request")
	date := r.Timestamp.UTC().Format("2006-01-02")
	secretDate := hmacSHA256([]byte("TC3"+r.SecretKey), date)
	secretService := hmacSHA256(secretDate, r.Service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, r.StringToSign()))

	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		tc3Algorithm, r.SecretID, r.credentialScope(),
		"content-type;host;x-tc-action", signature)

	headers := map[string]string{
		"Authorization":  authorization,
		"Content-Type":   tc3ContentType,
		"Host":           r.Host,
		"X-TC-Action":    r.Action,
		"X-TC-Version":   r.Version,
		"X-TC-Timestamp": fmt.Sprintf("%d", r.Timestamp.UTC().Unix()),
	}
	if r.Region != "" {
		headers["X-TC-Region"] = r.Region
	}
	return authorization, headers
}
