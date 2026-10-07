// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SessionCookie is the cookie carrying the session token.
const SessionCookie = "certcenter_session"

// Session is an authenticated caller.
type Session struct {
	User    string
	Expires time.Time
}

// SessionManager issues and verifies HMAC-signed session tokens. Tokens are
// stateless: "<base64url(user|expiry)>.<base64url(hmac)>". Rotating the key
// invalidates every outstanding session, which is the intended logout-all.
type SessionManager struct {
	key []byte
	ttl time.Duration
}

func NewSessionManager(key []byte, ttl time.Duration) *SessionManager {
	return &SessionManager{key: key, ttl: ttl}
}

func (m *SessionManager) Issue(user string, now time.Time) (string, error) {
	if user == "" {
		return "", errors.New("session: empty user")
	}
	if strings.Contains(user, "|") {
		return "", errors.New("session: user must not contain '|'")
	}
	payload := fmt.Sprintf("%s|%d", user, now.Add(m.ttl).Unix())
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return encoded + "." + m.sign(encoded), nil
}

func (m *SessionManager) Verify(token string, now time.Time) (Session, error) {
	encoded, sig, ok := strings.Cut(token, ".")
	if !ok || encoded == "" || sig == "" {
		return Session{}, errors.New("session: malformed token")
	}
	// Constant-time compare, and compare before decoding so a forged
	// payload is never parsed.
	if !hmac.Equal([]byte(sig), []byte(m.sign(encoded))) {
		return Session{}, errors.New("session: bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Session{}, errors.New("session: malformed payload")
	}
	user, expStr, ok := strings.Cut(string(raw), "|")
	if !ok || user == "" {
		return Session{}, errors.New("session: malformed payload")
	}
	unix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return Session{}, errors.New("session: malformed expiry")
	}
	expires := time.Unix(unix, 0)
	if !now.Before(expires) {
		return Session{}, errors.New("session: expired")
	}
	return Session{User: user, Expires: expires}, nil
}

func (m *SessionManager) sign(encoded string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// TTL exposes the configured lifetime so the cookie's MaxAge matches the
// token's expiry.
func (m *SessionManager) TTL() time.Duration { return m.ttl }
