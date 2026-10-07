// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package cloudsign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ACS3-HMAC-SHA256 is Aliyun's V3 request signature. The algorithm is
// reproduced from Aliyun's own specification and locked by acs3_test.go
// against the worked example in their documentation, so the expected
// values there are externally authoritative rather than a snapshot of
// this code.
const (
	acs3Algorithm = "ACS3-HMAC-SHA256"
	// acs3EmptyBodySHA256 is hex(sha256("")). Every parameter travels in
	// the query string, so the body is always empty.
	acs3EmptyBodySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// ACS3Request carries everything the signature covers.
type ACS3Request struct {
	AccessKeyID     string
	AccessKeySecret string
	Host            string
	Action          string
	Version         string
	Date            string // UTC, "2006-01-02T15:04:05Z"
	Nonce           string
	Params          map[string]string
}

// ACS3PercentEncode encodes per RFC 3986: A-Z a-z 0-9 - _ . ~ stay
// literal, every other byte becomes uppercase %XX. Multi-byte UTF-8 is
// encoded byte by byte, and a space becomes %20 — not '+', which would
// invalidate the signature.
func ACS3PercentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// ACS3CanonicalQuery joins the parameters sorted by key.
func ACS3CanonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, ACS3PercentEncode(k)+"="+ACS3PercentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

func (r ACS3Request) CanonicalQueryString() string {
	return ACS3CanonicalQuery(r.Params)
}

// signedHeaderNames returns the headers covered by the signature, sorted by
// lowercase name.
func (r ACS3Request) signedHeaderNames() ([]string, map[string]string) {
	headers := map[string]string{
		"host":                  r.Host,
		"x-acs-action":          r.Action,
		"x-acs-content-sha256":  acs3EmptyBodySHA256,
		"x-acs-date":            r.Date,
		"x-acs-signature-nonce": r.Nonce,
		"x-acs-version":         r.Version,
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, headers
}

func (r ACS3Request) CanonicalRequest() string {
	names, headers := r.signedHeaderNames()
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n)
		ch.WriteString(":")
		ch.WriteString(strings.TrimSpace(headers[n]))
		ch.WriteString("\n")
	}
	// CanonicalHeaders already ends in \n, so the extra \n below produces
	// the blank line the specification requires before SignedHeaders.
	return "POST\n/\n" + r.CanonicalQueryString() + "\n" +
		ch.String() + "\n" +
		strings.Join(names, ";") + "\n" +
		acs3EmptyBodySHA256
}

func (r ACS3Request) StringToSign() string {
	sum := sha256.Sum256([]byte(r.CanonicalRequest()))
	return acs3Algorithm + "\n" + hex.EncodeToString(sum[:])
}

// sign returns the Authorization header value, the exact query string that
// was signed, and every header to send.
//
// The query string is returned rather than rebuilt by the caller because
// the transmitted URL must be byte-identical to the signed one.
func (r ACS3Request) Sign() (string, string, map[string]string) {
	names, headers := r.signedHeaderNames()

	mac := hmac.New(sha256.New, []byte(r.AccessKeySecret))
	mac.Write([]byte(r.StringToSign()))
	signature := hex.EncodeToString(mac.Sum(nil))

	// No space after the commas — the format is exact.
	authorization := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		acs3Algorithm, r.AccessKeyID, strings.Join(names, ";"), signature)

	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		out[k] = v
	}
	out["Authorization"] = authorization

	return authorization, r.CanonicalQueryString(), out
}

// RandomNonce returns a signature nonce. Exported because both the DNS and
// the CDN callers need one.
func RandomNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for signing; fall back to the clock
		// so the request fails at the API rather than panicking here.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}
