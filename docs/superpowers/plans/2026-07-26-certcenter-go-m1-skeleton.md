# CertCenter Go 重写 — 里程碑 1：骨架 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 搭出可运行的 Go 服务骨架——配置加载、SQLite 存储、会话认证、HTTP 路由与嵌入式 SPA 托管，跑得起来且有测试覆盖，但还不含 ACME/部署/总线。

**Architecture:** 标准库 `net/http` 加 Go 1.22 路由模式（`"GET /api/x/{id}"`），`Server` 结构体聚合依赖并由 `Routes()` 装配 mux，中间件为 `limitBody` + `originGuard` 两层包裹。存储层是 `Store` 接口加唯一的 SQLite 实现，测试跑内存 SQLite。认证是 HMAC 签名的会话令牌，写 HttpOnly Cookie 并支持 Bearer 回退。布局对齐 `~/plat101`。

**Tech Stack:** Go 1.26、`modernc.org/sqlite`（纯 Go 免 cgo）、`github.com/pelletier/go-toml/v2`、`golang.org/x/crypto/bcrypt`、`log/slog`、`embed`。

设计依据：`docs/superpowers/specs/2026-07-26-certcenter-go-rewrite-design.md`（下称"规范"）。本计划实现规范的里程碑 1。

## Global Constraints

- 模块路径 `github.com/mrhaoxx/certcenter`，Go 版本 `1.26`。
- 每个新建的 `.go` 文件以这三行开头，一字不差：
  ```go
  // Copyright 2026 The CertCenter Authors.
  //
  // SPDX-License-Identifier: Apache-2.0
  ```
- 不引入 web 框架（gin/chi/echo 一律禁止），HTTP 只用标准库。
- 不引入 ORM，SQL 手写。
- `CGO_ENABLED=0` 必须能编译——因此 SQLite 驱动只能是 `modernc.org/sqlite`，不得换成 `mattn/go-sqlite3`。
- 测试用内存 SQLite（`:memory:`）跑真实 `schema.sql`，**不写平行的内存 Store 实现**（理由见规范 §4）。
- SQLite 连接池固定 `SetMaxOpenConns(1)`。
- 错误响应统一信封 `{"code","message","detail"}`，`code` 用大写下划线常量。
- 本里程碑**不碰** `backend/`（Rust）与 `frontend/`（Next.js）目录，它们在里程碑 8 才删除。
- 每个任务结束时 `go build ./... && go test ./... && go vet ./...` 必须全绿。

---

### Task 1: Go 模块骨架、嵌入式 SPA 与 healthz

建出模块、`web` 嵌入包和最小可服务的 `Server`。本任务不建 `cmd/`——入口在 Task 8 才完整装配，避免中途返工。

**Files:**
- Create: `go.mod`
- Create: `.gitignore`
- Create: `web/embed.go`
- Create: `web/dist/index.html`（占位，**必须提交进版本库**）
- Create: `internal/server/server.go`
- Test: `internal/server/server_test.go`

**Interfaces:**
- Consumes: 无（首个任务）
- Produces:
  - `web.Dist embed.FS` — 嵌入 `web/dist` 全部内容
  - `server.Server` 结构体（本任务为空壳，后续任务往里加字段）
  - `func (s *Server) Routes() http.Handler`
  - `func (s *Server) writeJSON(w http.ResponseWriter, status int, v any)`
  - `func (s *Server) writeErr(w http.ResponseWriter, status int, code, msg string, detail any)`

- [ ] **Step 1: 建模块与 gitignore**

`go.mod`：

```
module github.com/mrhaoxx/certcenter

go 1.26
```

`.gitignore`（`*.db` 那几行是安全项——当前仓库的 `backend/certcenter.db` 含私钥却未被忽略，见规范 §16）：

```gitignore
# Go
/bin/
*.test
cover.out
vendor/

# 数据库（含私钥，绝不入库）
*.db
*.db-wal
*.db-shm

# 前端
node_modules/
web/tsconfig.tsbuildinfo
# 真实的 Vite 产物；web/dist/index.html 占位文件是被跟踪的，
# 这样没装 Node 也能 go build
web/dist/assets/

# 编辑器 / 系统
.DS_Store
.idea/
.vscode/
```

- [ ] **Step 2: 建 web 嵌入包与占位产物**

`web/embed.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package web embeds the built SPA. web/dist ships a committed
// placeholder so `go build ./...` works without Node; the real bundle
// comes from milestone 7.
package web

import "embed"

//go:embed all:dist
var Dist embed.FS
```

`web/dist/index.html`：

```html
<!doctype html>
<meta charset="utf-8">
<title>CertCenter</title>
<p>SPA placeholder — run hack/build-webui.sh to produce the real bundle.</p>
```

- [ ] **Step 3: 写失败的测试**

`internal/server/server_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthz(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}

func TestSPAFallback(t *testing.T) {
	srv := &Server{}
	tests := []struct {
		name, path string
		wantBody   string
	}{
		{"根路径返回 index.html", "/", "SPA placeholder"},
		{"无扩展名的前端路由回退 index.html", "/certificates/12", "SPA placeholder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestMissingAssetIs404(t *testing.T) {
	// 含 "." 的路径走文件服务，不做 SPA 回退——否则缺失的 .js
	// 会返回 200 的 HTML，浏览器报语法错误而非 404，极难排查。
	srv := &Server{}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/nope.js", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestUnknownAPIPathIsJSONError(t *testing.T) {
	srv := &Server{}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != "NOT_FOUND" {
		t.Errorf("code = %q, want NOT_FOUND", body.Code)
	}
}
```

- [ ] **Step 4: 跑测试确认失败**

Run: `go test ./internal/server/ -v`
Expected: 编译失败，`undefined: Server`

- [ ] **Step 5: 实现 server.go**

`internal/server/server.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package server implements the CertCenter backend: the JSON API, session
// auth, and the embedded SPA.
package server

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"

	"github.com/mrhaoxx/certcenter/web"
)

// Server carries the backend's dependencies. Later milestones add fields
// (issuer, deployer, bus) — Routes() is the single place they get wired
// into the HTTP surface.
type Server struct{}

// apiError is the single error envelope for every API response.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (s *Server) writeErr(w http.ResponseWriter, status int, code, msg string, detail any) {
	s.writeJSON(w, status, apiError{Code: code, Message: msg, Detail: detail})
}

// Routes assembles the full handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Any unmatched /api/ path is a JSON 404, never an SPA fallback — a
	// mistyped endpoint must not return HTML to a fetch() caller.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		s.writeErr(w, http.StatusNotFound, "NOT_FOUND", "no such endpoint", nil)
	})

	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		panic(err) // the embed layout is fixed at build time
	}
	files := http.FileServerFS(dist)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A path containing "." is an asset request: serve it or 404.
		// Everything else is a client-side route: serve index.html.
		if strings.Contains(r.URL.Path, ".") {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFileFS(w, r, dist, "index.html")
	})

	return mux
}
```

- [ ] **Step 6: 跑测试确认通过**

Run: `go test ./... -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 7: 提交**

```bash
git add go.mod .gitignore web/embed.go web/dist/index.html internal/server/server.go internal/server/server_test.go
git commit -m "feat(go): module skeleton, embedded SPA, healthz"
```

---

### Task 2: 配置包（加载、校验、稀疏合并）

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`
- Modify: `go.mod`（加 go-toml 依赖）

**Interfaces:**
- Consumes: 无
- Produces:
  - `config.Config` 及其子结构 `ServerConfig`/`DatabaseConfig`/`AuthConfig`/`DNSVerificationConfig`/`BusConfig`
  - `func Default() *Config`
  - `func Load(path string) (*Config, error)`
  - `func (c *Config) Validate() error`
  - `func (c *Config) MergeResolved(tomlText string) error` — 稀疏覆盖，供总线配置中心推送用（里程碑 6 调用）
  - `func (c *Config) DoHServer() string`、`func (c *Config) DNSMaxRetries() int` — 带默认值的取值器

- [ ] **Step 1: 写失败的测试**

`internal/config/config_test.go`：

```go
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
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/config/ -v`
Expected: 编译失败，`undefined: Config`

- [ ] **Step 3: 加依赖**

Run: `go get github.com/pelletier/go-toml/v2@v2.4.3`

- [ ] **Step 4: 实现 config.go**

`internal/config/config.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package config loads CertCenter's TOML configuration. The same schema is
// pushed by the ServerAgent config center at runtime (see MergeResolved),
// so field names are an external contract — renaming one breaks the push.
package config

import (
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
```

import 需要 `"bytes"`、`"fmt"`、`"os"` 与 `"github.com/pelletier/go-toml/v2"`。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/config/ -v`
Expected: 全部 PASS。若 `TestLoadMissingSectionFails` 失败，说明 `Load` 的必需段落检查没生效，检查 Step 4 里那两行守卫。

- [ ] **Step 6: 提交**

```bash
git add go.mod go.sum internal/config/
git commit -m "feat(config): TOML load, validate, sparse merge for config center"
```

---

### Task 3: 数据库 schema 与连接

建出完整 schema（所有表，后续里程碑直接用）与 SQLite 连接，以及测试辅助。

**Files:**
- Create: `internal/db/schema.sql`
- Create: `internal/db/sqlite.go`
- Create: `internal/db/testdb.go`
- Test: `internal/db/sqlite_test.go`
- Modify: `go.mod`

**Interfaces:**
- Consumes: 无
- Produces:
  - `func Open(path string) (*SQLite, error)` — 打开、设 pragma、跑 schema
  - `type SQLite struct { ... }`，含 `func (s *SQLite) Close() error`
  - `func NewTestDB(t *testing.T) *SQLite` — 内存库，跑真实 schema
  - `var Schema string`（embed 的 schema.sql）

- [ ] **Step 1: 写 schema.sql**

`internal/db/schema.sql`——逐字取自规范 §4：

```sql
CREATE TABLE IF NOT EXISTS acme_accounts (
  id            INTEGER PRIMARY KEY,
  name          TEXT    NOT NULL,
  directory_url TEXT    NOT NULL,
  email         TEXT    NOT NULL,
  account_url   TEXT,
  private_key   TEXT    NOT NULL,
  validity_days INTEGER NOT NULL DEFAULT 90,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dns_providers (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,
  config     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS certificates (
  id              INTEGER PRIMARY KEY,
  domain          TEXT    NOT NULL,
  sans            TEXT    NOT NULL DEFAULT '[]',
  acme_account_id INTEGER NOT NULL REFERENCES acme_accounts(id),
  dns_provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  cert_pem        TEXT,
  chain_pem       TEXT,
  key_pem         TEXT,
  serial          TEXT,
  not_before      TEXT,
  not_after       TEXT,
  renew_after     TEXT,
  validity_days   INTEGER NOT NULL DEFAULT 90,
  status          TEXT    NOT NULL DEFAULT 'pending',
  last_error      TEXT,
  auto_renew      INTEGER NOT NULL DEFAULT 1,
  retry_count     INTEGER NOT NULL DEFAULT 0,
  retry_after     TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deploy_targets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,
  config     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deployments (
  id               INTEGER PRIMARY KEY,
  certificate_id   INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deploy_target_id INTEGER NOT NULL REFERENCES deploy_targets(id) ON DELETE CASCADE,
  status           TEXT    NOT NULL DEFAULT 'pending',
  last_deployed_at TEXT,
  last_error       TEXT,
  UNIQUE(certificate_id, deploy_target_id)
);

CREATE TABLE IF NOT EXISTS runs (
  id             INTEGER PRIMARY KEY,
  kind           TEXT    NOT NULL,
  certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deployment_id  INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  attempt        INTEGER NOT NULL,
  trigger        TEXT    NOT NULL,
  status         TEXT    NOT NULL DEFAULT 'running',
  error          TEXT,
  started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  finished_at    TEXT
);
CREATE INDEX IF NOT EXISTS runs_cert ON runs(certificate_id, id DESC);

CREATE TABLE IF NOT EXISTS events (
  id      INTEGER PRIMARY KEY,
  run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  seq     INTEGER NOT NULL,
  type    TEXT    NOT NULL,
  message TEXT    NOT NULL,
  detail  TEXT,
  level   TEXT    NOT NULL DEFAULT 'info',
  at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id, seq);

CREATE TABLE IF NOT EXISTS operation_logs (
  id            INTEGER PRIMARY KEY,
  action        TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   INTEGER,
  detail        TEXT,
  operator      TEXT NOT NULL DEFAULT 'admin',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS operation_logs_recent ON operation_logs(id DESC);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

- [ ] **Step 2: 写失败的测试**

`internal/db/sqlite_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"sort"
	"testing"
)

func TestSchemaCreatesEveryTable(t *testing.T) {
	s := NewTestDB(t)

	rows, err := s.DB.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var got []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		got = append(got, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)

	want := []string{
		"acme_accounts", "certificates", "deploy_targets", "deployments",
		"dns_providers", "events", "operation_logs", "runs", "settings",
	}
	if len(got) != len(want) {
		t.Fatalf("tables = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tables = %v, want %v", got, want)
			break
		}
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	// 现有 Rust 实现声明了外键却从未启用 PRAGMA，级联全靠手写 SQL。
	// 这个测试锁住"外键真的开着"。
	s := NewTestDB(t)

	var on int
	if err := s.DB.QueryRow("PRAGMA foreign_keys").Scan(&on); err != nil {
		t.Fatal(err)
	}
	if on != 1 {
		t.Fatalf("PRAGMA foreign_keys = %d, want 1", on)
	}

	// 指向不存在的账户必须被拒绝。
	_, err := s.DB.Exec(`INSERT INTO certificates (domain, acme_account_id, dns_provider_id)
	                     VALUES ('x.example.com', 999, 999)`)
	if err == nil {
		t.Fatal("insert with dangling FK succeeded, want a constraint error")
	}
}

func TestDeletingCertificateCascades(t *testing.T) {
	s := NewTestDB(t)
	certID := seedCertificate(t, s)

	if _, err := s.DB.Exec(`INSERT INTO runs (kind, certificate_id, attempt, trigger)
	                        VALUES ('issue', ?, 1, 'manual')`, certID); err != nil {
		t.Fatal(err)
	}
	var runID int64
	if err := s.DB.QueryRow("SELECT id FROM runs WHERE certificate_id = ?", certID).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO events (run_id, seq, type, message)
	                        VALUES (?, 1, 'start', 'hello')`, runID); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DB.Exec("DELETE FROM certificates WHERE id = ?", certID); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"runs", "events"} {
		var n int
		if err := s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still has %d rows after deleting the certificate, want 0", table, n)
		}
	}
}

func TestOpenFileDBUsesWAL(t *testing.T) {
	// 内存库的 journal_mode 返回 "memory"，所以 WAL 只能在文件库上断言。
	path := filepath.Join(t.TempDir(), "cc.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() = %v", err)
	}
	defer s.Close()

	var mode string
	if err := s.DB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want %q", mode, "wal")
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	// schema 用 CREATE TABLE IF NOT EXISTS，重开已有库不能报错。
	path := filepath.Join(t.TempDir(), "cc.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	second, err := Open(path)
	if err != nil {
		t.Fatalf("reopening an existing database failed: %v", err)
	}
	second.Close()
}

// seedCertificate 插入一条证书及其依赖的账户与 DNS 提供商，返回证书 id。
func seedCertificate(t *testing.T, s *SQLite) int64 {
	t.Helper()
	res, err := s.DB.Exec(`INSERT INTO acme_accounts (name, directory_url, email, private_key)
	                       VALUES ('le', 'https://acme.example/dir', 'a@b.c', 'PEM')`)
	if err != nil {
		t.Fatal(err)
	}
	acctID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.DB.Exec(`INSERT INTO dns_providers (name, kind, config)
	                      VALUES ('cf', 'cloudflare', '{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	res, err = s.DB.Exec(`INSERT INTO certificates (domain, acme_account_id, dns_provider_id)
	                      VALUES ('x.example.com', ?, ?)`, acctID, dnsID)
	if err != nil {
		t.Fatal(err)
	}
	certID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return certID
}
```

- [ ] **Step 3: 跑测试确认失败**

Run: `go test ./internal/db/ -v`
Expected: 编译失败，`undefined: NewTestDB`

- [ ] **Step 4: 加依赖**

Run: `go get modernc.org/sqlite@v1.54.0`

- [ ] **Step 5: 实现 sqlite.go 与 testdb.go**

`internal/db/sqlite.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package db is CertCenter's persistence layer: SQLite via a pure-Go
// driver so the binary builds with CGO_ENABLED=0.
package db

import (
	"database/sql"
	_ "embed"
	"fmt"
	"net/url"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var Schema string

// SQLite is the Store implementation.
type SQLite struct {
	DB *sql.DB
}

// Open opens (creating if absent) the database at path, applies the
// pragmas, and runs the schema.
func Open(path string) (*SQLite, error) {
	return open(dsn(path))
}

// dsn builds a modernc.org/sqlite DSN. foreign_keys is ON because the
// schema relies on ON DELETE CASCADE; WAL plus a busy timeout keeps the
// scheduler's writes from colliding with a request.
func dsn(path string) string {
	return "file:" + url.PathEscape(path) +
		"?_pragma=foreign_keys(on)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)"
}

func open(dsn string) (*SQLite, error) {
	handle, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite has a single writer. Writes here are rare (issuance, deploys,
	// events), so one connection trades negligible throughput for the
	// whole class of SQLITE_BUSY races.
	handle.SetMaxOpenConns(1)

	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	if _, err := handle.Exec(Schema); err != nil {
		handle.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &SQLite{DB: handle}, nil
}

func (s *SQLite) Close() error { return s.DB.Close() }
```

`internal/db/testdb.go`（非 `_test.go`，好让 `internal/server` 的测试也能用）：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import "testing"

// NewTestDB returns an in-memory store running the real schema.sql, closed
// when the test ends. Handler and store tests share it: exercising the
// actual SQL — especially the renewal-selection date arithmetic — is worth
// more than a hand-written fake that can silently diverge.
func NewTestDB(t *testing.T) *SQLite {
	t.Helper()
	s, err := open("file::memory:?_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
```

- [ ] **Step 6: 跑测试确认通过**

Run: `go test ./internal/db/ -v`
Expected: 五个测试全 PASS。`TestForeignKeysAreEnforced` 失败说明 DSN 的 `_pragma=foreign_keys(on)` 没生效；`TestOpenFileDBUsesWAL` 失败检查 `journal_mode(WAL)` 拼写。

- [ ] **Step 7: 提交**

```bash
git add go.mod go.sum internal/db/
git commit -m "feat(db): full schema, SQLite open with pragmas, in-memory test store"
```

---

### Task 4: Store 接口 —— 设置项与操作日志

M1 只需要认证要用的 settings 与审计要用的 operation_logs。后续里程碑各自往 `Store` 接口加自己的方法。

**Files:**
- Create: `internal/db/store.go`
- Modify: `internal/db/sqlite.go`（追加方法）
- Test: `internal/db/store_test.go`

**Interfaces:**
- Consumes: `db.SQLite`、`db.NewTestDB`（Task 3）
- Produces:
  - `type Store interface { GetSetting; SetSetting; AppendLog; ListLogs; Close }`
  - `type OperationLog struct{ ID int64; Action, ResourceType string; ResourceID *int64; Detail *string; Operator, CreatedAt string }`（JSON tag 即 API 形状）
  - `var ErrNotFound = errors.New("not found")`
  - `func (s *SQLite) GetSetting(ctx context.Context, key string) (string, error)`
  - `func (s *SQLite) SetSetting(ctx context.Context, key, value string) error`
  - `func (s *SQLite) AppendLog(ctx context.Context, l OperationLog) error`
  - `func (s *SQLite) ListLogs(ctx context.Context, limit, offset int) ([]OperationLog, error)`
  - 常量 `SettingAdminPasswordHash = "admin_password_hash"`

- [ ] **Step 1: 写失败的测试**

`internal/db/store_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"testing"
)

func TestSettingRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	if _, err := s.GetSetting(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSetting(missing) = %v, want ErrNotFound", err)
	}

	if err := s.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSetting(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v1" {
		t.Errorf("GetSetting = %q, want %q", got, "v1")
	}

	// 覆盖写：SetSetting 必须是 upsert，不能因主键冲突失败。
	if err := s.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatalf("overwriting a setting failed: %v", err)
	}
	got, err = s.GetSetting(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v2" {
		t.Errorf("GetSetting after overwrite = %q, want %q", got, "v2")
	}
}

func TestAppendAndListLogs(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	id := int64(7)
	detail := "created something"
	for _, l := range []OperationLog{
		{Action: "create", ResourceType: "certificate", ResourceID: &id, Detail: &detail, Operator: "admin"},
		{Action: "delete", ResourceType: "certificate", Operator: "admin"},
	} {
		if err := s.AppendLog(ctx, l); err != nil {
			t.Fatal(err)
		}
	}

	logs, err := s.ListLogs(ctx, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("len(logs) = %d, want 2", len(logs))
	}
	// 最新优先。
	if logs[0].Action != "delete" {
		t.Errorf("logs[0].Action = %q, want %q (newest first)", logs[0].Action, "delete")
	}
	if logs[0].ResourceID != nil {
		t.Errorf("logs[0].ResourceID = %v, want nil", *logs[0].ResourceID)
	}
	if logs[1].ResourceID == nil || *logs[1].ResourceID != 7 {
		t.Errorf("logs[1].ResourceID = %v, want 7", logs[1].ResourceID)
	}
	if logs[1].Detail == nil || *logs[1].Detail != detail {
		t.Errorf("logs[1].Detail = %v, want %q", logs[1].Detail, detail)
	}
	if logs[0].CreatedAt == "" {
		t.Error("CreatedAt is empty, want the DB default to be populated")
	}
}

func TestListLogsPaginates(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := s.AppendLog(ctx, OperationLog{Action: "a", ResourceType: "t", Operator: "admin"}); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name          string
		limit, offset int
		wantLen       int
	}{
		{"取前两条", 2, 0, 2},
		{"偏移后取两条", 2, 2, 2},
		{"偏移到尾部", 2, 4, 1},
		{"偏移越界", 2, 99, 0},
		{"limit 为 0 时用默认值", 0, 0, 5},
		{"limit 为负时用默认值", -3, 0, 5},
		{"limit 超上限时截到 500", 9999, 0, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs, err := s.ListLogs(ctx, tt.limit, tt.offset)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(logs), tt.wantLen)
			}
		})
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/db/ -run 'Setting|Logs' -v`
Expected: 编译失败，`s.GetSetting undefined`

- [ ] **Step 3: 写 store.go**

`internal/db/store.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a lookup by key or id finds no row.
var ErrNotFound = errors.New("not found")

// Setting keys.
const (
	// SettingAdminPasswordHash holds the live bcrypt hash. config's
	// auth.password_hash only seeds it on first boot, so changing the
	// password no longer means rewriting config.toml.
	SettingAdminPasswordHash = "admin_password_hash"
)

// Pagination bounds for ListLogs.
const (
	DefaultLogLimit = 100
	MaxLogLimit     = 500
)

// OperationLog is one audit entry. JSON tags are the API shape.
type OperationLog struct {
	ID           int64   `json:"id"`
	Action       string  `json:"action"`
	ResourceType string  `json:"resourceType"`
	ResourceID   *int64  `json:"resourceId"`
	Detail       *string `json:"detail"`
	Operator     string  `json:"operator"`
	CreatedAt    string  `json:"createdAt"`
}

// Store is the persistence boundary. Later milestones extend it with the
// certificate, account, provider, target, and run/event methods.
type Store interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error

	AppendLog(ctx context.Context, l OperationLog) error
	ListLogs(ctx context.Context, limit, offset int) ([]OperationLog, error)

	Close() error
}
```

- [ ] **Step 4: 在 sqlite.go 追加实现**

追加到 `internal/db/sqlite.go` 末尾，并把 `"context"` 加进 import：

```go
// 编译期断言：SQLite 满足 Store。
var _ Store = (*SQLite)(nil)

func (s *SQLite) GetSetting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get setting %q: %w", key, err)
	}
	return v, nil
}

func (s *SQLite) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

func (s *SQLite) AppendLog(ctx context.Context, l OperationLog) error {
	operator := l.Operator
	if operator == "" {
		operator = "admin"
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO operation_logs (action, resource_type, resource_id, detail, operator)
		 VALUES (?, ?, ?, ?, ?)`,
		l.Action, l.ResourceType, l.ResourceID, l.Detail, operator)
	if err != nil {
		return fmt.Errorf("append log: %w", err)
	}
	return nil
}

func (s *SQLite) ListLogs(ctx context.Context, limit, offset int) ([]OperationLog, error) {
	if limit <= 0 {
		limit = DefaultLogLimit
	}
	if limit > MaxLogLimit {
		limit = MaxLogLimit
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, action, resource_type, resource_id, detail, operator, created_at
		 FROM operation_logs ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list logs: %w", err)
	}
	defer rows.Close()

	logs := []OperationLog{}
	for rows.Next() {
		var l OperationLog
		if err := rows.Scan(&l.ID, &l.Action, &l.ResourceType, &l.ResourceID,
			&l.Detail, &l.Operator, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan log: %w", err)
		}
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
```

注意：返回的切片初始化为 `[]OperationLog{}` 而非 `nil`，这样 JSON 序列化出 `[]` 而不是 `null`——前端不必为空列表写特例。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/db/ -v`
Expected: 全部 PASS

- [ ] **Step 6: 提交**

```bash
git add internal/db/
git commit -m "feat(db): Store interface with settings and operation logs"
```

---

### Task 5: 会话管理器（HMAC 令牌）

**Files:**
- Create: `internal/server/session.go`
- Test: `internal/server/session_test.go`

**Interfaces:**
- Consumes: 无
- Produces:
  - `type Session struct { User string; Expires time.Time }`
  - `func NewSessionManager(key []byte, ttl time.Duration) *SessionManager`
  - `func (m *SessionManager) Issue(user string, now time.Time) (string, error)`
  - `func (m *SessionManager) Verify(token string, now time.Time) (Session, error)`
  - `const SessionCookie = "certcenter_session"`

- [ ] **Step 1: 写失败的测试**

`internal/server/session_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestIssueThenVerify(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	now := time.Unix(1_700_000_000, 0)

	tok, err := m.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := m.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Verify() = %v", err)
	}
	if sess.User != "admin" {
		t.Errorf("User = %q, want %q", sess.User, "admin")
	}
	if !sess.Expires.Equal(now.Add(time.Hour)) {
		t.Errorf("Expires = %v, want %v", sess.Expires, now.Add(time.Hour))
	}
}

func TestVerifyRejects(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	now := time.Unix(1_700_000_000, 0)
	valid, err := m.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}

	// 换一把密钥签的同一份载荷必须被拒——这是防伪造的核心。
	other := NewSessionManager([]byte("ffffffffffffffffffffffffffffffff"), time.Hour)
	forged, err := other.Issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		token string
		when  time.Time
	}{
		{"空令牌", "", now},
		{"缺分隔符", "garbage", now},
		{"签名被篡改", valid[:len(valid)-4] + "AAAA", now},
		{"载荷被篡改", strings.Replace(valid, "a", "b", 1), now},
		{"用别的密钥签的", forged, now},
		{"已过期", valid, now.Add(2 * time.Hour)},
		{"刚好到期", valid, now.Add(time.Hour)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := m.Verify(tt.token, tt.when); err == nil {
				t.Error("Verify() = nil error, want rejection")
			}
		})
	}
}

func TestIssueRejectsEmptyUser(t *testing.T) {
	m := NewSessionManager(testKey, time.Hour)
	if _, err := m.Issue("", time.Now()); err == nil {
		t.Error("Issue(\"\") = nil error, want rejection")
	}
}

func TestUserWithSeparatorIsRejected(t *testing.T) {
	// 载荷用 "|" 分隔字段；用户名里带 "|" 会让解析产生歧义，
	// 必须在签发时就拒绝，而不是留到验证时才发现。
	m := NewSessionManager(testKey, time.Hour)
	if _, err := m.Issue("ad|min", time.Now()); err == nil {
		t.Error("Issue with a separator in the user = nil error, want rejection")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/server/ -run Session -v`
Expected: 编译失败，`undefined: NewSessionManager`

- [ ] **Step 3: 实现 session.go**

`internal/server/session.go`：

```go
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
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/server/ -run Session -v`
Expected: 全部 PASS。注意"刚好到期"用例依赖 `!now.Before(expires)`（到期即失效），若写成 `now.After(expires)` 该用例会失败。

- [ ] **Step 5: 提交**

```bash
git add internal/server/session.go internal/server/session_test.go
git commit -m "feat(auth): HMAC session tokens"
```

---

### Task 6: 认证中间件与登录/登出/me

**Files:**
- Modify: `internal/server/server.go`（给 `Server` 加字段、加中间件、挂路由）
- Create: `internal/server/auth.go`
- Test: `internal/server/auth_test.go`
- Modify: `internal/server/server_test.go`（构造函数改动的适配）
- Modify: `go.mod`（加 bcrypt）

**Interfaces:**
- Consumes: `db.Store`、`db.NewTestDB`、`db.SettingAdminPasswordHash`（Task 3/4）；`SessionManager`、`Session`、`SessionCookie`（Task 5）；`config.Config`（Task 2）
- Produces:
  - `Server` 新增字段：`DB db.Store`、`Sessions *SessionManager`、`Config func() *config.Config`、`AllowedOrigins map[string]bool`、`SecureCookies bool`
  - `func (s *Server) sessionFrom(w http.ResponseWriter, r *http.Request) (Session, bool)` — 失败时已写好 401
  - `func (s *Server) limitBody(next http.Handler) http.Handler`
  - `func (s *Server) originGuard(next http.Handler) http.Handler`
  - `func (s *Server) requireSession(h http.HandlerFunc) http.HandlerFunc`
  - handler：`handleLogin`、`handleLogout`、`handleMe`
  - `const maxRequestBody = 256 << 10`

- [ ] **Step 1: 写失败的测试**

`internal/server/auth_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
)

const testPassword = "correct horse battery"

// newTestServer builds a Server backed by an in-memory database with the
// admin password already seeded.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	store := db.NewTestDB(t)

	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcryptCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetSetting(context.Background(), db.SettingAdminPasswordHash, string(hash)); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Auth.SessionKey = string(testKey)
	cfg.Auth.Username = "admin"

	return &Server{
		DB:             store,
		Sessions:       NewSessionManager(testKey, time.Hour),
		Config:         func() *config.Config { return cfg },
		AllowedOrigins: map[string]bool{"https://cc.example.com": true},
	}
}

func postJSON(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestLoginSuccessSetsCookie(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
	}
	var body struct{ User string `json:"user"` }
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.User != "admin" {
		t.Errorf("user = %q, want admin", body.User)
	}

	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			found = c
		}
	}
	if found == nil {
		t.Fatal("no session cookie set")
	}
	if !found.HttpOnly {
		t.Error("cookie is not HttpOnly — a XSS could then read the session")
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", found.SameSite)
	}
	if _, err := srv.Sessions.Verify(found.Value, time.Now()); err != nil {
		t.Errorf("cookie value does not verify: %v", err)
	}
}

func TestLoginFailures(t *testing.T) {
	tests := []struct {
		name, body string
		wantStatus int
		wantCode   string
	}{
		{"密码错误", `{"username":"admin","password":"nope"}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"用户名错误", `{"username":"root","password":"` + testPassword + `"}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"空密码", `{"username":"admin","password":""}`, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"请求体不是 JSON", `not json`, http.StatusBadRequest, "BAD_REQUEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			rec := postJSON(t, srv, "/api/auth/login", tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			var body apiError
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", body.Code, tt.wantCode)
			}
			if strings.Contains(strings.ToLower(body.Message), testPassword) {
				t.Error("error message leaks the password")
			}
		})
	}
}

func TestProtectedRouteRequiresSession(t *testing.T) {
	srv := newTestServer(t)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status without a session = %d, want 401", rec.Code)
	}

	tok, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Cookie 认证", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body)
		}
		var body struct{ User string `json:"user"` }
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.User != "admin" {
			t.Errorf("user = %q, want admin", body.User)
		}
	})

	t.Run("Bearer 认证", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("伪造令牌", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.Header.Set("Authorization", "Bearer bogus.sig")
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestLogoutClearsCookie(t *testing.T) {
	srv := newTestServer(t)
	rec := postJSON(t, srv, "/api/auth/logout", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			if c.MaxAge >= 0 {
				t.Errorf("MaxAge = %d, want negative so the browser drops it", c.MaxAge)
			}
			return
		}
	}
	t.Error("logout did not send a clearing cookie")
}

func TestOriginGuard(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		name, method, origin string
		wantBlocked          bool
	}{
		{"允许的来源可写", http.MethodPost, "https://cc.example.com", false},
		{"陌生来源被拒", http.MethodPost, "https://evil.example.com", true},
		{"无 Origin 头放行（curl/脚本）", http.MethodPost, "", false},
		{"GET 不受限", http.MethodGet, "https://evil.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/auth/login", strings.NewReader(`{}`))
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			srv.Routes().ServeHTTP(rec, req)

			blocked := rec.Code == http.StatusForbidden
			if blocked != tt.wantBlocked {
				t.Errorf("blocked = %v (status %d), want %v", blocked, rec.Code, tt.wantBlocked)
			}
		})
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	srv := newTestServer(t)
	huge := `{"username":"admin","password":"` + strings.Repeat("x", maxRequestBody+1) + `"}`
	rec := postJSON(t, srv, "/api/auth/login", huge)
	if rec.Code == http.StatusOK {
		t.Fatalf("status = 200, want a rejection for an oversized body")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/server/ -run 'Login|Protected|Logout|Origin|Oversized' -v`
Expected: 编译失败，`unknown field DB in struct literal`

- [ ] **Step 3: 加依赖**

Run: `go get golang.org/x/crypto@v0.54.0`

- [ ] **Step 4: 扩展 server.go**

把 `internal/server/server.go` 里的 `Server` 定义替换为：

```go
// Server carries the backend's dependencies. Later milestones add fields
// (issuer, deployer, bus) — Routes() is the single place they get wired
// into the HTTP surface.
type Server struct {
	DB       db.Store
	Sessions *SessionManager

	// Config reads the live configuration; the bus can swap it at runtime,
	// so handlers must call this per request rather than caching a copy.
	Config func() *config.Config

	// AllowedOrigins are the origins accepted for mutating requests.
	// Empty disables the check (single-origin deployments behind a proxy).
	AllowedOrigins map[string]bool
	SecureCookies  bool
}
```

import 补上：

```go
	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
```

在同文件追加中间件与会话取值：

```go
// maxRequestBody caps mutating request bodies so a huge or slowly
// dribbled payload can't exhaust memory or pin a goroutine.
const maxRequestBody = 256 << 10 // 256 KiB

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// limitBody bounds mutating request bodies. GET is untouched so it never
// interferes with the SSE stream added in milestone 4.
func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// originGuard rejects cross-origin mutating requests. Cookie auth needs
// this: without it any page could POST to the API with the user's cookie
// attached. A request with no Origin header (curl, a script) is allowed —
// browsers always send one on cross-origin writes.
func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isMutating(r.Method) && len(s.AllowedOrigins) > 0 {
			if o := r.Header.Get("Origin"); o != "" && !s.AllowedOrigins[o] {
				s.writeErr(w, http.StatusForbidden, "FORBIDDEN", "cross-origin request rejected", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// sessionFrom authenticates the request. On failure it has already written
// the 401, so the caller just returns.
func (s *Server) sessionFrom(w http.ResponseWriter, r *http.Request) (Session, bool) {
	token := ""
	if c, err := r.Cookie(SessionCookie); err == nil {
		token = c.Value
	} else if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(a, "Bearer "))
	}
	if token == "" {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "not logged in", nil)
		return Session{}, false
	}
	sess, err := s.Sessions.Verify(token, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid session", nil)
		return Session{}, false
	}
	return sess, true
}

// requireSession wraps a handler so it only runs for an authenticated caller.
func (s *Server) requireSession(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessionFrom(w, r); !ok {
			return
		}
		h(w, r)
	}
}

// decodeJSON reads a JSON body, rejecting unknown fields so a typo in a
// client payload fails loudly.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
```

import 再补 `"strings"`（已有）、`"time"`。

把 `Routes()` 里 healthz 之后、`/api/` 兜底之前插入路由注册，并把返回值改为带两层中间件：

```go
	s.registerAuthRoutes(mux)
```

`Routes()` 末尾的 `return mux` 改为：

```go
	return s.limitBody(s.originGuard(mux))
```

- [ ] **Step 5: 实现 auth.go**

`internal/server/auth.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/subtle"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// bcryptCost is deliberately above bcrypt.DefaultCost (10). Spec §6 fixes
// it at 12; keep the constant so hashing and the tests can never drift.
const bcryptCost = 12

func (s *Server) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.requireSession(s.handleMe))
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}

	cfg := s.Config()
	hash, err := s.DB.GetSetting(r.Context(), db.SettingAdminPasswordHash)
	if err != nil {
		// SeedAdminPassword runs at startup, so a missing hash means the
		// service is misconfigured rather than the caller being wrong.
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not read credentials", nil)
		return
	}

	// Evaluate both factors unconditionally: bcrypt runs even when the
	// username is wrong, so response timing does not reveal which half
	// failed. (Short-circuiting on the username would make a valid
	// username measurably slower.)
	passwordOK := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) == nil
	userOK := subtle.ConstantTimeCompare([]byte(req.Username), []byte(cfg.Auth.Username)) == 1
	if !passwordOK || !userOK {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid username or password", nil)
		return
	}

	token, err := s.Sessions.Issue(cfg.Auth.Username, time.Now())
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not issue a session", nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.Sessions.TTL().Seconds()),
	})
	s.writeJSON(w, http.StatusOK, map[string]string{"user": cfg.Auth.Username})
}

func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
	// Sessions are stateless, so logout is just dropping the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessionFrom(w, r)
	if !ok {
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"user": sess.User,
	})
}
```

- [ ] **Step 6: 修 Task 1 的测试**

`server_test.go` 里四处 `&Server{}` 换成 `newTestServer(t)`，因为 `Routes()` 现在会用到 `Sessions` 与 `Config`。healthz、SPA 回退、404 三个测试的断言不变。

- [ ] **Step 7: 跑测试确认通过**

Run: `go test ./... -v`
Expected: 全部 PASS。`TestOversizedBodyRejected` 若返回 200，检查 `Routes()` 返回值是否真的包了 `limitBody`。

- [ ] **Step 8: 提交**

```bash
git add go.mod go.sum internal/server/
git commit -m "feat(auth): session cookie login, origin guard, body limit"
```

---

### Task 7: 管理员密码播种与改密码

**Files:**
- Modify: `internal/server/auth.go`
- Test: `internal/server/password_test.go`

**Interfaces:**
- Consumes: Task 6 全部产出
- Produces:
  - `func SeedAdminPassword(ctx context.Context, store db.Store, configHash string) error` — 仅当 settings 无值时写入
  - handler `handleChangePassword` 挂在 `PUT /api/me/password`
  - `const minPasswordLength = 8`

- [ ] **Step 1: 写失败的测试**

`internal/server/password_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mrhaoxx/certcenter/internal/db"
)

func TestSeedAdminPassword(t *testing.T) {
	ctx := context.Background()

	t.Run("空库时播种", func(t *testing.T) {
		store := db.NewTestDB(t)
		if err := SeedAdminPassword(ctx, store, "$2a$12$fromconfig"); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetSetting(ctx, db.SettingAdminPasswordHash)
		if err != nil {
			t.Fatal(err)
		}
		if got != "$2a$12$fromconfig" {
			t.Errorf("hash = %q, want the config value", got)
		}
	})

	t.Run("已有值时不覆盖", func(t *testing.T) {
		// 这是本任务的核心保证：改过密码后重启，配置文件里的旧
		// 散列不能把用户的新密码顶掉。
		store := db.NewTestDB(t)
		if err := store.SetSetting(ctx, db.SettingAdminPasswordHash, "$2a$12$changedbyuser"); err != nil {
			t.Fatal(err)
		}
		if err := SeedAdminPassword(ctx, store, "$2a$12$fromconfig"); err != nil {
			t.Fatal(err)
		}
		got, err := store.GetSetting(ctx, db.SettingAdminPasswordHash)
		if err != nil {
			t.Fatal(err)
		}
		if got != "$2a$12$changedbyuser" {
			t.Errorf("hash = %q, want the stored value to survive", got)
		}
	})

	t.Run("配置里也没有散列时报错", func(t *testing.T) {
		store := db.NewTestDB(t)
		if err := SeedAdminPassword(ctx, store, ""); err == nil {
			t.Error("SeedAdminPassword with an empty hash = nil, want an error")
		}
	})
}

func putJSON(t *testing.T, srv *Server, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: token})
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestChangePassword(t *testing.T) {
	srv := newTestServer(t)
	token, err := srv.Sessions.Issue("admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	rec := putJSON(t, srv, "/api/me/password",
		`{"oldPassword":"`+testPassword+`","newPassword":"a-brand-new-secret"}`, token)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body)
	}

	// 新密码可用。
	hash, err := srv.DB.GetSetting(context.Background(), db.SettingAdminPasswordHash)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("a-brand-new-secret")) != nil {
		t.Error("the new password does not verify against the stored hash")
	}
	// 旧密码失效。
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testPassword)) == nil {
		t.Error("the old password still verifies")
	}

	// 审计留痕。
	logs, err := srv.DB.ListLogs(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Action != "change_password" {
		t.Errorf("logs = %+v, want one change_password entry", logs)
	}
}

func TestChangePasswordRejections(t *testing.T) {
	tests := []struct {
		name, body  string
		withSession bool
		wantStatus  int
		wantCode    string
	}{
		{"未登录", `{"oldPassword":"x","newPassword":"yyyyyyyy"}`, false, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"旧密码错误", `{"oldPassword":"wrong","newPassword":"yyyyyyyy"}`, true, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"新密码太短", `{"oldPassword":"` + testPassword + `","newPassword":"short"}`, true, http.StatusBadRequest, "BAD_REQUEST"},
		{"请求体不是 JSON", `nope`, true, http.StatusBadRequest, "BAD_REQUEST"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			token := ""
			if tt.withSession {
				var err error
				token, err = srv.Sessions.Issue("admin", time.Now())
				if err != nil {
					t.Fatal(err)
				}
			}
			rec := putJSON(t, srv, "/api/me/password", tt.body, token)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tt.wantStatus, rec.Body)
			}
			var body apiError
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", body.Code, tt.wantCode)
			}

			// 失败时存储的散列不能变。
			hash, err := srv.DB.GetSetting(context.Background(), db.SettingAdminPasswordHash)
			if err != nil {
				t.Fatal(err)
			}
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(testPassword)) != nil {
				t.Error("a failed change modified the stored password")
			}
		})
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/server/ -run 'Seed|ChangePassword' -v`
Expected: 编译失败，`undefined: SeedAdminPassword`

- [ ] **Step 3: 实现**

追加到 `internal/server/auth.go`，并在 `registerAuthRoutes` 里加一行：

```go
	mux.HandleFunc("PUT /api/me/password", s.requireSession(s.handleChangePassword))
```

```go
// minPasswordLength is the floor for a new password.
const minPasswordLength = 8

// SeedAdminPassword writes the config's bcrypt hash into settings the
// first time the service starts. It never overwrites an existing value:
// once the admin changes their password through the API, the hash in
// config.toml is stale and must not win on the next restart.
func SeedAdminPassword(ctx context.Context, store db.Store, configHash string) error {
	if _, err := store.GetSetting(ctx, db.SettingAdminPasswordHash); err == nil {
		return nil // already seeded
	} else if !errors.Is(err, db.ErrNotFound) {
		return err
	}
	if configHash == "" {
		return errors.New("auth.password_hash is empty and no password is stored; cannot seed the admin account")
	}
	return store.SetSetting(ctx, db.SettingAdminPasswordHash, configHash)
}

type changePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "malformed request body", nil)
		return
	}
	if len(req.NewPassword) < minPasswordLength {
		s.writeErr(w, http.StatusBadRequest, "BAD_REQUEST",
			fmt.Sprintf("the new password must be at least %d characters", minPasswordLength), nil)
		return
	}

	current, err := s.DB.GetSetting(r.Context(), db.SettingAdminPasswordHash)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not read credentials", nil)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(current), []byte(req.OldPassword)) != nil {
		s.writeErr(w, http.StatusUnauthorized, "UNAUTHORIZED", "current password is incorrect", nil)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcryptCost)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not hash the password", nil)
		return
	}
	if err := s.DB.SetSetting(r.Context(), db.SettingAdminPasswordHash, string(hash)); err != nil {
		s.writeErr(w, http.StatusInternalServerError, "INTERNAL", "could not store the password", nil)
		return
	}
	_ = s.DB.AppendLog(r.Context(), db.OperationLog{
		Action: "change_password", ResourceType: "auth", Operator: "admin",
	})
	w.WriteHeader(http.StatusNoContent)
}
```

import 补 `"context"`、`"errors"`、`"fmt"`。`bcryptCost` 已在 Task 6 定义，直接用。

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./... -v`
Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
git add internal/server/
git commit -m "feat(auth): seed admin password from config, change password via API"
```

---

### Task 8: 入口装配

把配置、数据库、Server 串起来成为可运行的二进制，含优雅退出与"配置无效时不监听、等总线推送"的启动语义（规范 §5）。

**Files:**
- Create: `cmd/certcenter/main.go`
- Create: `config.example.toml`（替换仓库根现有的同名文件内容）
- Test: `cmd/certcenter/main_test.go`

**Interfaces:**
- Consumes: `config.Load`/`Validate`/`Addr`/`Clone`、`db.Open`、`server.Server`/`NewSessionManager`/`SeedAdminPassword`
- Produces: 可执行文件；`func originOf(rawURL string) string`（供测试）

- [ ] **Step 1: 写失败的测试**

`cmd/certcenter/main_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestOriginOf(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"https://cc.example.com", "https://cc.example.com"},
		{"https://cc.example.com/", "https://cc.example.com"},
		{"https://cc.example.com/ui/index.html", "https://cc.example.com"},
		{"http://localhost:3001/x", "http://localhost:3001"},
		{"", ""},
		{"not a url", ""},
	}
	for _, tt := range tests {
		if got := originOf(tt.in); got != tt.want {
			t.Errorf("originOf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitNonEmpty(t *testing.T) {
	got := splitNonEmpty(" a , ,b,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("splitNonEmpty = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitNonEmpty = %v, want %v", got, want)
		}
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./cmd/certcenter/ -v`
Expected: 编译失败，`undefined: originOf`

- [ ] **Step 3: 实现 main.go**

`cmd/certcenter/main.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Command certcenter serves the CertCenter control plane: ACME certificate
// issuance and renewal over DNS-01, deployment to SSH hosts / webhooks /
// CDNs / the ServerAgent config center, and the embedded SPA.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/server"
)

const sessionTTL = 24 * time.Hour

func main() {
	var (
		configPath  string
		listen      string
		externalURL string
		extraOrigin string
	)
	flag.StringVar(&configPath, "config", "config.toml", "path to the TOML config file")
	flag.StringVar(&listen, "listen", "", "override the configured listen address")
	flag.StringVar(&externalURL, "external-url", "",
		"external base URL of the UI (https enables Secure cookies and the Origin check)")
	flag.StringVar(&extraOrigin, "extra-origins", "",
		"comma-separated additional origins accepted for mutating requests")
	flag.Parse()

	// Positional argument keeps the Rust CLI's habit working: certcenter /data/config.toml
	if arg := flag.Arg(0); arg != "" {
		configPath = arg
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fatal(fmt.Errorf("load config: %w", err))
		}
		slog.Warn("config file not found, using defaults", "path", configPath)
		cfg = config.Default()
	}
	if listen != "" {
		host, port, perr := splitListen(listen)
		if perr != nil {
			fatal(perr)
		}
		cfg.Server.Host, cfg.Server.Port = host, port
	}

	// TODO(milestone 6): fetch and merge the config center's rendered TOML
	// before validating, and keep watching for pushes.

	if err := cfg.Validate(); err != nil {
		// Milestone 6 lets a config push start the service later. Until the
		// bus exists, an invalid config is fatal — silently serving nothing
		// would be worse than failing loudly.
		fatal(fmt.Errorf("config validation failed: %w", err))
	}

	store, err := db.Open(cfg.Database.Path)
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := server.SeedAdminPassword(ctx, store, cfg.Auth.PasswordHash); err != nil {
		fatal(err)
	}

	origin := originOf(externalURL)
	allowed := map[string]bool{}
	if origin != "" {
		allowed[origin] = true
	}
	for _, e := range splitNonEmpty(extraOrigin) {
		if o := originOf(e); o != "" {
			allowed[o] = true
		}
	}

	// The bus can replace the config at runtime, so handlers read it
	// through an atomic pointer rather than closing over one snapshot.
	live := &atomic.Pointer[config.Config]{}
	live.Store(cfg)

	srv := &server.Server{
		DB:             store,
		Sessions:       server.NewSessionManager([]byte(cfg.Auth.SessionKey), sessionTTL),
		Config:         live.Load,
		AllowedOrigins: allowed,
		SecureCookies:  strings.HasPrefix(origin, "https://"),
	}

	// No ReadTimeout/WriteTimeout: they would cut off the SSE stream added
	// in milestone 4. Header and idle timeouts bound slow-header and idle
	// socket abuse; body size is capped in the handler chain.
	httpSrv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("certcenter listening", "addr", cfg.Addr(), "database", cfg.Database.Path)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
	slog.Info("shutting down")
}

// originOf reduces a URL to its scheme://host origin for the CSRF check.
func originOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func splitListen(addr string) (string, int, error) {
	host, portStr, ok := strings.Cut(addr, ":")
	if !ok {
		return "", 0, fmt.Errorf("--listen must be host:port, got %q", addr)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port <= 0 {
		return "", 0, fmt.Errorf("--listen has an invalid port: %q", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(err error) {
	slog.Error("fatal", "err", err)
	os.Exit(1)
}
```

- [ ] **Step 4: 更新 config.example.toml**

替换仓库根 `config.example.toml` 的内容（`session_key` 换名、去掉已入库的字段说明）：

```toml
[server]
host = "0.0.0.0"
port = 3001

[database]
path = "certcenter.db"

[auth]
# HMAC key for session tokens; at least 32 bytes.
# Generate with: openssl rand -hex 32
session_key = "change-this-to-a-random-secret-string"
username = "admin"
# Seeds the admin password on first boot only — afterwards the database is
# authoritative and changing the password here has no effect.
# Generate with: htpasswd -nbBC 12 "" "your-password" | cut -d: -f2
password_hash = "$2b$12$frYPFyn9.CpYoHj6aHLe6.jFGKC9a8DjotMrNuVhNgk5hjY3IOJJy"

[dns_verification]
# skip = false
# doh_server = "https://cloudflare-dns.com/dns-query"
# max_retries = 12

# [bus]
# url = "ws://serveragent:9900/ws"
# service_id = "certcenter"
# token = "..."
# management_url = "ws://serveragent:9901/api/events/ws"
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./... && go vet ./... && go build ./...`
Expected: 全绿

- [ ] **Step 6: 端到端手工验证**

```bash
cd "$(mktemp -d)"
KEY=$(openssl rand -hex 32)
cat > config.toml <<EOF
[server]
host = "127.0.0.1"
port = 3111

[database]
path = "cc.db"

[auth]
session_key = "$KEY"
username = "admin"
password_hash = "\$2b\$12\$frYPFyn9.CpYoHj6aHLe6.jFGKC9a8DjotMrNuVhNgk5hjY3IOJJy"
EOF
go run github.com/mrhaoxx/certcenter/cmd/certcenter -config config.toml &
sleep 2
curl -sS localhost:3111/healthz; echo
curl -sS -i -X POST localhost:3111/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | head -20
curl -sS localhost:3111/api/me; echo
kill %1
```

Expected：`healthz` 回 `ok`；登录返回 200、`Set-Cookie: certcenter_session=...`；无 Cookie 的 `/api/me` 返回 401 的 JSON 错误信封。

- [ ] **Step 7: 提交**

```bash
git add cmd/ config.example.toml
git commit -m "feat(cmd): wire config, database, and server into a runnable binary"
```

---

## 完成标准

里程碑 1 完成时：

- `go build ./... && go test ./... && go vet ./...` 全绿，且 `CGO_ENABLED=0 go build ./...` 也能过。
- 二进制能起来，`/healthz` 可用，SPA 占位页可访问，登录/登出/查身份/改密码可用。
- 数据库九张表建好，外键与 WAL 生效。
- 配置能加载、校验，且稀疏合并对总线推送就绪（里程碑 6 直接调用）。
- Rust 与 Next.js 目录**未被触碰**。

## 交接给里程碑 2 的接口

后续里程碑依赖本里程碑的这些产出，签名不应再变：

- `db.Store` 接口（里程碑 2 起各自追加方法）、`db.SQLite`、`db.NewTestDB(t)`、`db.ErrNotFound`、`db.OperationLog`
- `server.Server` 结构体（追加字段即可）、`s.writeJSON`/`s.writeErr`/`s.requireSession`/`s.sessionFrom`/`decodeJSON`、`apiError` 信封
- `config.Config`（含 `DoHServer()`、`DNSMaxRetries()`、`Clone()`、`MergeResolved()`）
- `internal/db/schema.sql` 已含全部九张表，里程碑 2–5 不需要改 schema

## 留给里程碑 6 的两处待办

本里程碑为了让服务能独立跑起来，在两个地方有意偏离规范 §5，里程碑 6 必须回来改：

1. **配置校验失败时当前是 fatal 退出**，而规范要求"不监听、等配置中心推送"。在总线不存在的 M1 阶段，挂着不监听等于无声卡死，不如响亮失败。M6 接入总线后改回规范语义。`main.go` 里对应位置有 `TODO(milestone 6)` 标记。
2. **启动时未拉取配置中心的 `config.resolve`**，`main.go` 的同一处标记了插入点。`config.MergeResolved` 与 `config.Clone` 已实现且有测试，M6 直接调用即可。
