// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validKey = "0123456789abcdef0123456789abcdef" // 32 字节

func validConfig() *Config {
	c := Default()
	c.Auth.SessionKey = validKey
	return c
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // 空表示期望通过
	}{
		{"合法配置", func(*Config) {}, ""},
		{"host 为空", func(c *Config) { c.Server.Host = "" }, "server.host"},
		{"port 为 0", func(c *Config) { c.Server.Port = 0 }, "server.port"},
		{"数据库路径为空", func(c *Config) { c.Database.Path = "" }, "database.path"},
		{"session_key 为空", func(c *Config) { c.Auth.SessionKey = "" }, "auth.session_key"},
		{"session_key 太短", func(c *Config) { c.Auth.SessionKey = "short" }, "auth.session_key"},
		{"session_key 是占位值", func(c *Config) { c.Auth.SessionKey = PlaceholderSessionKey }, "auth.session_key"},
		{"用户名为空", func(c *Config) { c.Auth.Username = "" }, "auth.username"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			err := c.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := `
[server]
host = "127.0.0.1"
port = 8080

[database]
path = "/data/cc.db"

[auth]
session_key = "` + validKey + `"
username = "root"
password_hash = "$2a$12$hash"

[dns_verification]
skip = true
max_retries = 5

[bus]
url = "ws://bus:9900/ws"
service_id = "certcenter"
token = "t0ken"
management_url = "ws://bus:9901/api/events/ws"
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if c.Server.Host != "127.0.0.1" || c.Server.Port != 8080 {
		t.Errorf("server = %+v", c.Server)
	}
	if c.Database.Path != "/data/cc.db" {
		t.Errorf("database.path = %q", c.Database.Path)
	}
	if c.Auth.Username != "root" {
		t.Errorf("auth.username = %q", c.Auth.Username)
	}
	if !c.DNSVerification.Skip {
		t.Error("dns_verification.skip = false, want true")
	}
	if got := c.DNSMaxRetries(); got != 5 {
		t.Errorf("DNSMaxRetries() = %d, want 5", got)
	}
	if c.Bus == nil || c.Bus.ServiceID != "certcenter" {
		t.Errorf("bus = %+v", c.Bus)
	}
}

func TestLoadMissingSectionFails(t *testing.T) {
	// 文件存在但缺必需段落必须报错，而不是静默用默认值——
	// 否则一个手抖删掉 [auth] 的配置会让服务带着默认密码起来。
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("[server]\nhost = \"0.0.0.0\"\nport = 3001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() = nil error, want failure on missing [auth]/[database]")
	}
}

func TestLoadRejectsUnknownKey(t *testing.T) {
	// 配置中心和人手都可能写错键名；静默忽略会让人对着一个
	// "明明配了却不生效" 的选项调半天。
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[database]\npath = \"x.db\"\n\n[auth]\nsession_key = \"" + validKey + "\"\nusernme = \"typo\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load() = nil error, want failure on an unknown key")
	}
}

func TestLoadAppliesDefaultsForOmittedOptionalFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[database]\npath = \"x.db\"\n\n[auth]\nsession_key = \"" + validKey + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() = %v", err)
	}
	if c.Server.Host != "0.0.0.0" || c.Server.Port != 3001 {
		t.Errorf("server = %+v, want the 0.0.0.0:3001 default", c.Server)
	}
	if c.Auth.Username != "admin" {
		t.Errorf("auth.username = %q, want the admin default", c.Auth.Username)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a minimal config should validate, got %v", err)
	}
}

func TestDefaultsForOptionalDNSFields(t *testing.T) {
	c := Default()
	if got := c.DoHServer(); got != DefaultDoHServer {
		t.Errorf("DoHServer() = %q, want %q", got, DefaultDoHServer)
	}
	if got := c.DNSMaxRetries(); got != DefaultDNSMaxRetries {
		t.Errorf("DNSMaxRetries() = %d, want %d", got, DefaultDNSMaxRetries)
	}
}

func TestMergeResolvedIsSparse(t *testing.T) {
	c := validConfig()
	c.Server.Host = "0.0.0.0"
	c.Server.Port = 3001
	c.Auth.Username = "admin"
	c.DNSVerification.Skip = false

	// 只推 port 和 skip，其余字段必须保持原值。
	err := c.MergeResolved("[server]\nport = 9999\n\n[dns_verification]\nskip = true\n")
	if err != nil {
		t.Fatalf("MergeResolved() = %v", err)
	}
	if c.Server.Port != 9999 {
		t.Errorf("port = %d, want 9999", c.Server.Port)
	}
	if c.Server.Host != "0.0.0.0" {
		t.Errorf("host = %q, want it unchanged", c.Server.Host)
	}
	if c.Auth.Username != "admin" {
		t.Errorf("username = %q, want it unchanged", c.Auth.Username)
	}
	if !c.DNSVerification.Skip {
		t.Error("skip = false, want true")
	}
}

func TestMergeResolvedNeverTouchesBus(t *testing.T) {
	// 总线连接由本地文件固定；配置中心不能改自己的接入方式，
	// 否则一次错误推送就能把服务从总线上永久踢下线。
	c := validConfig()
	c.Bus = &BusConfig{URL: "ws://real:9900/ws", ServiceID: "certcenter", Token: "keep"}

	err := c.MergeResolved("[bus]\nurl = \"ws://evil:1/ws\"\ntoken = \"stolen\"\n")
	if err != nil {
		t.Fatalf("MergeResolved() = %v", err)
	}
	if c.Bus.URL != "ws://real:9900/ws" || c.Bus.Token != "keep" {
		t.Errorf("bus = %+v, want it unchanged", c.Bus)
	}
}

func TestMergeResolvedRejectsGarbage(t *testing.T) {
	c := validConfig()
	if err := c.MergeResolved("this is not = = toml"); err == nil {
		t.Fatal("MergeResolved() = nil error, want a parse failure")
	}
}

func TestCloneIsDeep(t *testing.T) {
	// 总线合并推送时先 Clone 再改，若指针字段是浅拷贝，
	// 一次失败的校验就会把已生效的配置改坏。
	c := validConfig()
	doh := "https://dns.example/query"
	retries := 3
	c.DNSVerification.DoHServer = &doh
	c.DNSVerification.MaxRetries = &retries
	mgmt := "ws://bus:9901/x"
	c.Bus = &BusConfig{URL: "ws://bus:9900/ws", ManagementURL: &mgmt}

	cp := c.Clone()
	*cp.DNSVerification.DoHServer = "https://mutated/"
	*cp.DNSVerification.MaxRetries = 99
	cp.Bus.URL = "ws://mutated/"
	*cp.Bus.ManagementURL = "ws://mutated/x"

	if c.DoHServer() != doh {
		t.Errorf("original DoHServer = %q, want %q", c.DoHServer(), doh)
	}
	if c.DNSMaxRetries() != 3 {
		t.Errorf("original MaxRetries = %d, want 3", c.DNSMaxRetries())
	}
	if c.Bus.URL != "ws://bus:9900/ws" {
		t.Errorf("original bus.URL = %q, want it unchanged", c.Bus.URL)
	}
	if *c.Bus.ManagementURL != mgmt {
		t.Errorf("original bus.ManagementURL = %q, want it unchanged", *c.Bus.ManagementURL)
	}
}

func TestAddr(t *testing.T) {
	c := Default()
	c.Server.Host = "127.0.0.1"
	c.Server.Port = 3001
	if got := c.Addr(); got != "127.0.0.1:3001" {
		t.Errorf("Addr() = %q, want %q", got, "127.0.0.1:3001")
	}
}
