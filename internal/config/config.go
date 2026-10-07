// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package config loads CertCenter's TOML configuration. The same schema is
// pushed by the ServerAgent config center at runtime (see MergeResolved),
// so field names are an external contract — renaming one breaks the push.
package config

import (
	"bytes"
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Defaults applied where an optional field is unset.
const (
	DefaultDoHServer     = "https://cloudflare-dns.com/dns-query"
	DefaultDNSMaxRetries = 12
	minSessionKeyLen     = 32

	// PlaceholderSessionKey is the value shipped in config.example.toml.
	// Validate rejects it so a copy-pasted example can never sign real
	// sessions.
	PlaceholderSessionKey = "change-this-to-a-random-secret-string"
)

type Config struct {
	Server          ServerConfig          `toml:"server"`
	Database        DatabaseConfig        `toml:"database"`
	Auth            AuthConfig            `toml:"auth"`
	DNSVerification DNSVerificationConfig `toml:"dns_verification"`
	Bus             *BusConfig            `toml:"bus"`
}

type ServerConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type DatabaseConfig struct {
	Path string `toml:"path"`
}

type AuthConfig struct {
	// SessionKey is the HMAC key for session tokens (>= 32 bytes).
	SessionKey string `toml:"session_key"`
	Username   string `toml:"username"`
	// PasswordHash seeds the admin password on first boot only; after that
	// the settings table is authoritative (see server.SeedAdminPassword).
	PasswordHash string `toml:"password_hash"`
}

type DNSVerificationConfig struct {
	Skip bool `toml:"skip"`
	// Pointers so "unset" is distinguishable from "set to zero" — needed
	// for the sparse merge.
	DoHServer  *string `toml:"doh_server"`
	MaxRetries *int    `toml:"max_retries"`
}

type BusConfig struct {
	URL           string  `toml:"url"`
	ServiceID     string  `toml:"service_id"`
	Token         string  `toml:"token"`
	ManagementURL *string `toml:"management_url"`
}

func Default() *Config {
	return &Config{
		Server:   ServerConfig{Host: "0.0.0.0", Port: 3001},
		Database: DatabaseConfig{Path: "certcenter.db"},
		Auth: AuthConfig{
			SessionKey: PlaceholderSessionKey,
			Username:   "admin",
		},
	}
}

// DoHServer returns the configured DoH resolver or the default.
func (c *Config) DoHServer() string {
	if c.DNSVerification.DoHServer != nil && *c.DNSVerification.DoHServer != "" {
		return *c.DNSVerification.DoHServer
	}
	return DefaultDoHServer
}

// DNSMaxRetries returns the configured propagation retry count or the default.
func (c *Config) DNSMaxRetries() int {
	if c.DNSVerification.MaxRetries != nil && *c.DNSVerification.MaxRetries > 0 {
		return *c.DNSVerification.MaxRetries
	}
	return DefaultDNSMaxRetries
}

// Addr is the listen address.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// Load reads and parses a config file. Unknown keys are rejected so a typo
// fails loudly instead of being silently ignored.
//
// Decoding starts from a zero Config, NOT from Default(): go-toml leaves
// absent keys untouched, so pre-filling defaults would make the
// required-section guards below unreachable — a file missing [auth]
// entirely would silently inherit the default admin credentials.
// Defaults for genuinely optional fields are applied after the guards.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := toml.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Database.Path == "" {
		return nil, fmt.Errorf("parse %s: [database].path is required", path)
	}
	if c.Auth.SessionKey == "" {
		return nil, fmt.Errorf("parse %s: [auth].session_key is required", path)
	}
	if c.Server.Host == "" {
		c.Server.Host = "0.0.0.0"
	}
	if c.Server.Port == 0 {
		c.Server.Port = 3001
	}
	if c.Auth.Username == "" {
		c.Auth.Username = "admin"
	}
	return &c, nil
}

func (c *Config) Validate() error {
	switch {
	case c.Server.Host == "":
		return fmt.Errorf("server.host is empty")
	case c.Server.Port <= 0 || c.Server.Port > 65535:
		return fmt.Errorf("server.port is out of range: %d", c.Server.Port)
	case c.Database.Path == "":
		return fmt.Errorf("database.path is empty")
	case c.Auth.Username == "":
		return fmt.Errorf("auth.username is empty")
	case c.Auth.SessionKey == "" || c.Auth.SessionKey == PlaceholderSessionKey:
		return fmt.Errorf("auth.session_key is not configured")
	case len(c.Auth.SessionKey) < minSessionKeyLen:
		return fmt.Errorf("auth.session_key must be at least %d bytes, got %d",
			minSessionKeyLen, len(c.Auth.SessionKey))
	}
	return nil
}

// resolvedPatch mirrors Config with every field optional. Decoding into it
// is what makes MergeResolved sparse: a key absent from the pushed TOML
// stays nil and leaves the running value alone. [bus] is deliberately
// absent — the bus connection is fixed by the local file, so a bad push
// can never disconnect us permanently.
type resolvedPatch struct {
	Server *struct {
		Host *string `toml:"host"`
		Port *int    `toml:"port"`
	} `toml:"server"`
	Database *struct {
		Path *string `toml:"path"`
	} `toml:"database"`
	Auth *struct {
		SessionKey   *string `toml:"session_key"`
		Username     *string `toml:"username"`
		PasswordHash *string `toml:"password_hash"`
	} `toml:"auth"`
	DNSVerification *struct {
		Skip       *bool   `toml:"skip"`
		DoHServer  *string `toml:"doh_server"`
		MaxRetries *int    `toml:"max_retries"`
	} `toml:"dns_verification"`
}

// MergeResolved overlays the config center's rendered TOML onto c. Only
// keys present in the push are changed.
func (c *Config) MergeResolved(tomlText string) error {
	var p resolvedPatch
	if err := toml.Unmarshal([]byte(tomlText), &p); err != nil {
		return fmt.Errorf("parse resolved config: %w", err)
	}
	if p.Server != nil {
		assign(&c.Server.Host, p.Server.Host)
		assign(&c.Server.Port, p.Server.Port)
	}
	if p.Database != nil {
		assign(&c.Database.Path, p.Database.Path)
	}
	if p.Auth != nil {
		assign(&c.Auth.SessionKey, p.Auth.SessionKey)
		assign(&c.Auth.Username, p.Auth.Username)
		assign(&c.Auth.PasswordHash, p.Auth.PasswordHash)
	}
	if p.DNSVerification != nil {
		assign(&c.DNSVerification.Skip, p.DNSVerification.Skip)
		if p.DNSVerification.DoHServer != nil {
			c.DNSVerification.DoHServer = p.DNSVerification.DoHServer
		}
		if p.DNSVerification.MaxRetries != nil {
			c.DNSVerification.MaxRetries = p.DNSVerification.MaxRetries
		}
	}
	return nil
}

func assign[T any](dst *T, src *T) {
	if src != nil {
		*dst = *src
	}
}

// Clone returns a deep copy, used to merge a push without mutating the
// config the running handlers are reading.
func (c *Config) Clone() *Config {
	cp := *c
	if c.DNSVerification.DoHServer != nil {
		v := *c.DNSVerification.DoHServer
		cp.DNSVerification.DoHServer = &v
	}
	if c.DNSVerification.MaxRetries != nil {
		v := *c.DNSVerification.MaxRetries
		cp.DNSVerification.MaxRetries = &v
	}
	if c.Bus != nil {
		b := *c.Bus
		if c.Bus.ManagementURL != nil {
			v := *c.Bus.ManagementURL
			b.ManagementURL = &v
		}
		cp.Bus = &b
	}
	return &cp
}
