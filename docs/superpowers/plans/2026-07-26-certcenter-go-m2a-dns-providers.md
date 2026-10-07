# CertCenter Go 重写 — 里程碑 2a：DNS Provider 层 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 DNS-01 验证所需的 DNS 记录操作层——Provider 接口与工厂、Cloudflare 与阿里云两个实现、以及 DoH 传播校验，全部有测试覆盖且不依赖 ACME 库。

**Architecture:** `internal/dns` 定义 `Provider` 接口（`AddTXT`/`RemoveTXT`），工厂按 `kind` 字符串构造。两个实现都是手写 HTTP 客户端，端点可在包内替换以便 `httptest` 接管。阿里云的 ACS3-HMAC-SHA256 签名单独成文件，用阿里云官方文档的算例做黄金测试。DoH 校验独立于 Provider，供里程碑 2b 的 ACME solver 在 `Wait()` 中调用。

**Tech Stack:** Go 1.26、标准库 `net/http`、`crypto/hmac`、`crypto/sha256`、`encoding/json`。不引入任何云厂商 SDK。

设计依据：`docs/superpowers/specs/2026-07-26-certcenter-go-rewrite-design.md` §9（下称"规范"）。本计划实现规范里程碑 2 的 DNS 部分；账户管理与签发引擎见后续的 2b 计划。

## Global Constraints

- 模块路径 `github.com/mrhaoxx/certcenter`，Go 1.26。每个新 `.go` 文件以这三行开头，一字不差：
  ```go
  // Copyright 2026 The CertCenter Authors.
  //
  // SPDX-License-Identifier: Apache-2.0
  ```
- **不引入云厂商 SDK**（`alibaba-cloud-sdk-go`、`cloudflare-go` 一律禁止）。签名和请求手写——这正是我们没用 lego 内置 provider 的原因，引入 SDK 等于把省下的 234 个依赖模块又装回来。
- 配置 JSON 的键名是**数据契约**：Cloudflare 用 `api_token`/`zone_id`，阿里云用 `access_key_id`/`access_key_secret`/`domain`。不得改名——前端表单和现有部署的配置都按这些键写。
- 每个出网的 HTTP 客户端**必须设超时**。现有 Rust 实现全部没有超时，一次挂起的 DNS API 调用会无限期卡住签发。
- `CGO_ENABLED=0` 必须能编译。
- 每个任务结束时 `go build ./... && go test ./... && go vet ./...` 全绿。

## 与现有 Rust 实现的三处刻意行为差异

实现时不要"忠实移植"这三点，它们是已确认的缺陷（规范 §9、§14）：

1. **Cloudflare 的 `AddTXT` 不再先删同名记录。** Rust 版每次添加前先删掉同名 TXT，这正是 `example.com` 与 `*.example.com` 同证书时互相覆盖的根因——两个授权算出同一记录名但摘要不同，后写的删掉先写的，第一个授权随即验证失败。改为纯追加。
2. **响应体的 `success` 字段必须检查。** Rust 版只看 HTTP 状态码，Cloudflare 返回 200 但 `success:false` 会被当成成功。
3. **阿里云 RR 后缀不匹配时报错，不静默使用整个 FQDN。** Rust 版在 `domain` 配错时会在错误的 zone 里建出名为 `_acme-challenge.other.com` 的记录，然后验证莫名失败。

---

### Task 1: Provider 接口与工厂

**Files:**
- Create: `internal/dns/provider.go`
- Test: `internal/dns/provider_test.go`

**Interfaces:**
- Consumes: 无
- Produces:
  - `type Provider interface { AddTXT(ctx, name, value string) error; RemoveTXT(ctx, name, value string) error }`
  - `func New(kind, configJSON string) (Provider, error)`
  - `const KindCloudflare = "cloudflare"`、`const KindAliyun = "aliyun"`
  - `func Kinds() []string` — 供 API 层做校验与前端下拉
  - `var httpClient = &http.Client{Timeout: 30 * time.Second}` — 包内共享，两个 provider 都用

- [ ] **Step 1: 写失败的测试**

`internal/dns/provider_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"strings"
	"testing"
)

func TestNewUnknownKind(t *testing.T) {
	_, err := New("route53", `{}`)
	if err == nil {
		t.Fatal("New with an unknown kind = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "route53") {
		t.Errorf("error = %v, want it to name the unsupported kind", err)
	}
}

func TestNewRejectsMalformedConfig(t *testing.T) {
	for _, kind := range Kinds() {
		t.Run(kind, func(t *testing.T) {
			if _, err := New(kind, `not json`); err == nil {
				t.Error("New with malformed JSON = nil error, want failure")
			}
		})
	}
}

func TestNewRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name, kind, config, wantField string
	}{
		{"cloudflare 缺 api_token", KindCloudflare, `{"zone_id":"z"}`, "api_token"},
		{"cloudflare 缺 zone_id", KindCloudflare, `{"api_token":"t"}`, "zone_id"},
		{"aliyun 缺 access_key_id", KindAliyun, `{"access_key_secret":"s","domain":"example.com"}`, "access_key_id"},
		{"aliyun 缺 access_key_secret", KindAliyun, `{"access_key_id":"k","domain":"example.com"}`, "access_key_secret"},
		{"aliyun 缺 domain", KindAliyun, `{"access_key_id":"k","access_key_secret":"s"}`, "domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.kind, tt.config)
			if err == nil {
				t.Fatalf("New = nil error, want a complaint about %s", tt.wantField)
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Errorf("error = %v, want it to name %q", err, tt.wantField)
			}
		})
	}
}

func TestNewRejectsUnknownConfigKey(t *testing.T) {
	// 配置里写错键名（比如 zone 写成 zoneid）不能静默忽略，
	// 否则用户对着一个"明明填了却不生效"的表单排查半天。
	if _, err := New(KindCloudflare, `{"api_token":"t","zone_id":"z","zoneid":"oops"}`); err == nil {
		t.Error("New with an unknown config key = nil error, want failure")
	}
}

func TestKinds(t *testing.T) {
	kinds := Kinds()
	if len(kinds) != 2 {
		t.Fatalf("Kinds() = %v, want two entries", kinds)
	}
	seen := map[string]bool{}
	for _, k := range kinds {
		seen[k] = true
	}
	if !seen[KindCloudflare] || !seen[KindAliyun] {
		t.Errorf("Kinds() = %v, want it to contain %q and %q", kinds, KindCloudflare, KindAliyun)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/dns/ -v`
Expected: 编译失败，`undefined: New`

- [ ] **Step 3: 实现 provider.go**

`internal/dns/provider.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package dns manipulates the TXT records that satisfy ACME DNS-01
// challenges. Providers are hand-written HTTP clients rather than vendor
// SDKs: pulling in alibaba-cloud-sdk-go would add hundreds of dependency
// modules, which is exactly what choosing acmez over lego's built-in
// providers avoided.
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Provider creates and removes the TXT records for a DNS-01 challenge.
//
// name is always the fully-qualified record name with no trailing dot
// (e.g. "_acme-challenge.example.com"); value is the raw, unquoted digest.
//
// AddTXT must be additive: a single certificate covering both example.com
// and *.example.com produces two authorizations whose record names are
// identical but whose digests differ, so replacing same-name records would
// destroy the sibling challenge.
type Provider interface {
	AddTXT(ctx context.Context, name, value string) error
	RemoveTXT(ctx context.Context, name, value string) error
}

// Supported provider kinds. These strings are stored in
// dns_providers.kind and chosen by the UI — they are a data contract.
const (
	KindCloudflare = "cloudflare"
	KindAliyun     = "aliyun"
)

// Kinds lists the supported provider kinds, for API validation and the
// UI's picker.
func Kinds() []string {
	return []string{KindCloudflare, KindAliyun}
}

// httpClient is shared by every provider. The timeout is mandatory: the
// Rust implementation set none, so one hung DNS API call would stall an
// issuance indefinitely.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// New builds a provider from its stored kind and JSON config.
func New(kind, configJSON string) (Provider, error) {
	switch kind {
	case KindCloudflare:
		return newCloudflare(configJSON)
	case KindAliyun:
		return newAliyun(configJSON)
	default:
		return nil, fmt.Errorf("unsupported DNS provider kind: %q", kind)
	}
}

// decodeConfig unmarshals a provider config, rejecting unknown keys so a
// mistyped field fails at save time instead of silently doing nothing.
func decodeConfig(configJSON string, dst any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(configJSON)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse provider config: %w", err)
	}
	return nil
}

// requireFields reports the first named field whose value is empty.
func requireFields(fields map[string]string) error {
	// Sorted iteration would need another import; the callers pass few
	// fields and check order does not matter for correctness. Report every
	// missing field so a half-filled form is fixed in one round.
	var missing []string
	for name, value := range fields {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("provider config is missing required fields: %v", missing)
}
```

- [ ] **Step 4: 加两个临时桩让包能编译**

`newCloudflare` / `newAliyun` 要到 Task 2 / Task 4 才实现，但 `New` 现在就要引用它们。把下面两段放进 `provider.go` 末尾——它们做完整的配置校验（这是本任务的测试要覆盖的部分），然后返回明确的"未实现"错误，**绝不返回 `(nil, nil)`**，这样任务边界上测试是全绿的而不是"有一个预期失败"。

```go
// 临时桩，Task 2 用真实实现替换。
func newCloudflare(configJSON string) (Provider, error) {
	var cfg struct {
		APIToken string `json:"api_token"`
		ZoneID   string `json:"zone_id"`
	}
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, err
	}
	if err := requireFields(map[string]string{
		"api_token": cfg.APIToken, "zone_id": cfg.ZoneID,
	}); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("cloudflare provider not implemented yet")
}

// 临时桩，Task 4 用真实实现替换。
func newAliyun(configJSON string) (Provider, error) {
	var cfg struct {
		AccessKeyID     string `json:"access_key_id"`
		AccessKeySecret string `json:"access_key_secret"`
		Domain          string `json:"domain"`
	}
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, err
	}
	if err := requireFields(map[string]string{
		"access_key_id": cfg.AccessKeyID, "access_key_secret": cfg.AccessKeySecret,
		"domain": cfg.Domain,
	}); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("aliyun provider not implemented yet")
}
```

"构造成功"的正向用例放在 Task 4（两个 provider 都实现之后），因此本任务不需要断言 `New` 能返回可用实例。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/dns/ -v && go vet ./...`
Expected: 六个用例全部 PASS，无预期失败项。

- [ ] **Step 6: 提交**

```bash
git add internal/dns/provider.go internal/dns/provider_test.go
git commit -m "feat(dns): Provider interface and factory"
```

---

### Task 2: Cloudflare provider

**Files:**
- Create: `internal/dns/cloudflare.go`
- Modify: `internal/dns/provider.go`（删除 `newCloudflare` 桩）
- Test: `internal/dns/cloudflare_test.go`

**Interfaces:**
- Consumes: `Provider`、`decodeConfig`、`requireFields`、`httpClient`（Task 1）
- Produces:
  - `type cloudflare struct { token, zoneID, baseURL string }` — 实现 `Provider`
  - `func newCloudflare(configJSON string) (Provider, error)`
  - `const cloudflareAPI = "https://api.cloudflare.com/client/v4"`
  - `const cloudflareTXTTTL = 120`

- [ ] **Step 1: 写失败的测试**

`internal/dns/cloudflare_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newCloudflareWith builds a provider pointed at a test server.
func newCloudflareWith(t *testing.T, baseURL string) *cloudflare {
	t.Helper()
	return &cloudflare{token: "test-token", zoneID: "zone123", baseURL: baseURL}
}

func TestCloudflareAddTXT(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "digest-value"); err != nil {
		t.Fatalf("AddTXT() = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if want := "/zones/zone123/dns_records"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := "Bearer test-token"; gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}

	var body struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("request body is not JSON: %v (%q)", err, gotBody)
	}
	if body.Type != "TXT" {
		t.Errorf("type = %q, want TXT", body.Type)
	}
	if body.Name != "_acme-challenge.example.com" {
		t.Errorf("name = %q", body.Name)
	}
	if body.Content != "digest-value" {
		t.Errorf("content = %q", body.Content)
	}
	if body.TTL != cloudflareTXTTTL {
		t.Errorf("ttl = %d, want %d", body.TTL, cloudflareTXTTTL)
	}
}

func TestCloudflareAddTXTDoesNotDeleteFirst(t *testing.T) {
	// 回归测试：apex + 通配符同证书时，两个授权的记录名相同而摘要不同。
	// 添加前若先删同名记录，后一个挑战会毁掉前一个，第一个授权随即验证失败。
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec1"}}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "first"); err != nil {
		t.Fatal(err)
	}
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "second"); err != nil {
		t.Fatal(err)
	}

	for _, m := range methods {
		if m == http.MethodDelete {
			t.Fatalf("AddTXT issued a DELETE; requests = %v, want POST only", methods)
		}
	}
	if len(methods) != 2 {
		t.Errorf("requests = %v, want exactly two POSTs", methods)
	}
}

func TestCloudflareAddTXTRejectsSuccessFalse(t *testing.T) {
	// Rust 版只看 HTTP 状态码：200 + success:false 被当成成功，
	// 于是记录其实没建上，签发却继续往下走直到超时。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":false,"errors":[{"code":1004,"message":"DNS Validation Error"}]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("AddTXT with success:false = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "DNS Validation Error") {
		t.Errorf("error = %v, want it to surface the API message", err)
	}
}

func TestCloudflareAddTXTRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(context.Background(), "_acme-challenge.example.com", "v"); err == nil {
		t.Fatal("AddTXT on 403 = nil error, want failure")
	}
}

func TestCloudflareRemoveTXTDeletesOnlyExactMatch(t *testing.T) {
	// 服务端过滤语义在新版 API 里有 name.exact 之类的修饰符，不能依赖；
	// 客户端必须自己做精确匹配，否则会删掉别的挑战的记录。
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`{"success":true,"errors":[],"result":[
			  {"id":"want","type":"TXT","name":"_acme-challenge.example.com","content":"target"},
			  {"id":"other-value","type":"TXT","name":"_acme-challenge.example.com","content":"sibling"},
			  {"id":"other-name","type":"TXT","name":"_acme-challenge.sub.example.com","content":"target"}
			]}`))
		case http.MethodDelete:
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			deleted = append(deleted, parts[len(parts)-1])
			w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"x"}}`))
		}
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "want" {
		t.Errorf("deleted = %v, want exactly [want]", deleted)
	}
}

func TestCloudflareRemoveTXTIsIdempotent(t *testing.T) {
	// 清理路径会在失败重试后重复执行；记录已不存在必须视为成功。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"errors":[],"result":[]}`))
	}))
	defer srv.Close()

	p := newCloudflareWith(t, srv.URL)
	if err := p.RemoveTXT(context.Background(), "_acme-challenge.example.com", "gone"); err != nil {
		t.Errorf("RemoveTXT with no matching record = %v, want nil", err)
	}
}

func TestCloudflareContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := newCloudflareWith(t, srv.URL)
	if err := p.AddTXT(ctx, "_acme-challenge.example.com", "v"); err == nil {
		t.Error("AddTXT with a cancelled context = nil error, want failure")
	}
}

func TestNewCloudflareUsesRealEndpointByDefault(t *testing.T) {
	p, err := newCloudflare(`{"api_token":"t","zone_id":"z"}`)
	if err != nil {
		t.Fatal(err)
	}
	cf, ok := p.(*cloudflare)
	if !ok {
		t.Fatalf("newCloudflare returned %T, want *cloudflare", p)
	}
	if cf.baseURL != cloudflareAPI {
		t.Errorf("baseURL = %q, want %q", cf.baseURL, cloudflareAPI)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/dns/ -run Cloudflare -v`
Expected: 编译失败，`undefined: cloudflare`

- [ ] **Step 3: 实现 cloudflare.go**

`internal/dns/cloudflare.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	cloudflareAPI = "https://api.cloudflare.com/client/v4"
	// cloudflareTXTTTL keeps the challenge record short-lived so a stale
	// value cannot linger past a failed issuance.
	cloudflareTXTTTL = 120
)

// cloudflare talks to the Cloudflare v4 DNS API with a scoped API token.
// zoneID comes straight from the config: there is no zone lookup, so one
// provider record serves exactly one zone.
type cloudflare struct {
	token   string
	zoneID  string
	baseURL string
}

type cloudflareConfig struct {
	APIToken string `json:"api_token"`
	ZoneID   string `json:"zone_id"`
}

func newCloudflare(configJSON string) (Provider, error) {
	var cfg cloudflareConfig
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, err
	}
	if err := requireFields(map[string]string{
		"api_token": cfg.APIToken,
		"zone_id":   cfg.ZoneID,
	}); err != nil {
		return nil, err
	}
	return &cloudflare{token: cfg.APIToken, zoneID: cfg.ZoneID, baseURL: cloudflareAPI}, nil
}

// cloudflareEnvelope is the wrapper around every v4 response. success must
// be checked: the API can answer 200 with success:false, which the Rust
// implementation treated as a successful write.
type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (e cloudflareEnvelope) err() error {
	if e.Success {
		return nil
	}
	if len(e.Errors) == 0 {
		return fmt.Errorf("cloudflare API reported failure with no error detail")
	}
	msgs := make([]string, 0, len(e.Errors))
	for _, x := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%d %s", x.Code, x.Message))
	}
	return fmt.Errorf("cloudflare API error: %s", strings.Join(msgs, "; "))
}

// do performs a request and decodes the envelope, failing on both a
// non-2xx status and success:false.
func (c *cloudflare) do(ctx context.Context, method, path string, body any) (*cloudflareEnvelope, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var env cloudflareEnvelope
	if jsonErr := json.Unmarshal(raw, &env); jsonErr != nil {
		// A non-JSON body on an error status is more useful verbatim.
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("cloudflare %s %s: HTTP %d: %s",
				method, path, resp.StatusCode, truncate(string(raw), 500))
		}
		return nil, fmt.Errorf("cloudflare %s %s: malformed response: %w", method, path, jsonErr)
	}
	if err := env.err(); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("cloudflare %s %s: HTTP %d", method, path, resp.StatusCode)
	}
	return &env, nil
}

func (c *cloudflare) AddTXT(ctx context.Context, name, value string) error {
	// Purely additive — see the Provider doc comment on why same-name
	// records must not be replaced.
	_, err := c.do(ctx, http.MethodPost, "/zones/"+c.zoneID+"/dns_records", map[string]any{
		"type":    "TXT",
		"name":    name,
		"content": value,
		"ttl":     cloudflareTXTTTL,
	})
	return err
}

type cloudflareRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *cloudflare) RemoveTXT(ctx context.Context, name, value string) error {
	q := url.Values{}
	q.Set("type", "TXT")
	q.Set("name", name)
	env, err := c.do(ctx, http.MethodGet,
		"/zones/"+c.zoneID+"/dns_records?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	var records []cloudflareRecord
	if err := json.Unmarshal(env.Result, &records); err != nil {
		return fmt.Errorf("cloudflare: malformed record list: %w", err)
	}

	for _, rec := range records {
		// Match exactly on our own name and value. The server-side name
		// filter has modifiers (name.exact, name.contains) whose semantics
		// we must not depend on; a loose match would delete a sibling
		// challenge's record.
		if rec.Type != "TXT" || rec.Name != name || rec.Content != value {
			continue
		}
		if _, err := c.do(ctx, http.MethodDelete,
			"/zones/"+c.zoneID+"/dns_records/"+url.PathEscape(rec.ID), nil); err != nil {
			return err
		}
	}
	// No match is success: cleanup runs again after a retry, and the
	// desired state (record absent) already holds.
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
```

- [ ] **Step 4: 删掉 Task 1 的 Cloudflare 桩**

从 `internal/dns/provider.go` 末尾删除标注"临时桩，Task 2 替换"的 `newCloudflare` 函数。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/dns/ -v && go vet ./...`
Expected: 全部 PASS，无预期失败项。

- [ ] **Step 6: 提交**

```bash
git add internal/dns/
git commit -m "feat(dns): Cloudflare provider"
```

---

### Task 3: 阿里云 ACS3-HMAC-SHA256 签名

签名单独成任务：算错的话只有运行时才暴露，而阿里云官方文档给了完整算例，可以拿它当外部权威锚点。

**Files:**
- Create: `internal/dns/acs3.go`
- Test: `internal/dns/acs3_test.go`

**Interfaces:**
- Consumes: 无
- Produces:
  - `func acs3PercentEncode(s string) string`
  - `func acs3CanonicalQuery(params map[string]string) string`
  - `type acs3Request struct { AccessKeyID, AccessKeySecret, Host, Action, Version, Date, Nonce string; Params map[string]string }`
  - `func (r acs3Request) canonicalRequest() string`
  - `func (r acs3Request) stringToSign() string`
  - `func (r acs3Request) sign() (authorization string, query string, headers map[string]string)`
  - `const acs3EmptyBodySHA256`

- [ ] **Step 1: 写失败的测试**

`internal/dns/acs3_test.go`——期望值**逐字取自阿里云官方 V3 签名文档的"固定参数示例"**：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"strings"
	"testing"
)

// 官方算例（阿里云 SDK 文档《使用 V3 签名机制原生 HTTP 调用阿里云 OpenAPI》
// 的"固定参数示例"）。期望值来自阿里云自己的文档，而不是本实现的输出——
// 这样这个测试锁的是外部权威值，改坏签名一定会被抓住。
var officialExample = acs3Request{
	AccessKeyID:     "YourAccessKeyId",
	AccessKeySecret: "YourAccessKeySecret",
	Host:            "ecs.cn-shanghai.aliyuncs.com",
	Action:          "RunInstances",
	Version:         "2014-05-26",
	Date:            "2023-10-26T10:22:32Z",
	Nonce:           "3156853299f313e23d1673dc12e1703d",
	Params: map[string]string{
		"ImageId":  "win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd",
		"RegionId": "cn-shanghai",
	},
}

const (
	officialCanonicalRequest = "POST\n" +
		"/\n" +
		"ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai\n" +
		"host:ecs.cn-shanghai.aliyuncs.com\n" +
		"x-acs-action:RunInstances\n" +
		"x-acs-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
		"x-acs-date:2023-10-26T10:22:32Z\n" +
		"x-acs-signature-nonce:3156853299f313e23d1673dc12e1703d\n" +
		"x-acs-version:2014-05-26\n" +
		"\n" +
		"host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	officialStringToSign = "ACS3-HMAC-SHA256\n" +
		"7ea06492da5221eba5297e897ce16e55f964061054b7695beedaac1145b1e259"

	officialSignature = "06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
)

func TestACS3CanonicalRequestMatchesOfficialExample(t *testing.T) {
	got := officialExample.canonicalRequest()
	if got != officialCanonicalRequest {
		t.Errorf("canonicalRequest mismatch\n--- got ---\n%s\n--- want ---\n%s", got, officialCanonicalRequest)
	}
}

func TestACS3StringToSignMatchesOfficialExample(t *testing.T) {
	got := officialExample.stringToSign()
	if got != officialStringToSign {
		t.Errorf("stringToSign = %q, want %q", got, officialStringToSign)
	}
}

func TestACS3SignatureMatchesOfficialExample(t *testing.T) {
	auth, _, _ := officialExample.sign()
	if !strings.Contains(auth, "Signature="+officialSignature) {
		t.Errorf("Authorization = %q, want it to carry Signature=%s", auth, officialSignature)
	}
}

func TestACS3AuthorizationHeaderFormat(t *testing.T) {
	auth, _, _ := officialExample.sign()
	want := "ACS3-HMAC-SHA256 Credential=YourAccessKeyId," +
		"SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version," +
		"Signature=" + officialSignature
	if auth != want {
		t.Errorf("Authorization =\n  %q\nwant\n  %q", auth, want)
	}
}

func TestACS3PercentEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abcXYZ019", "abcXYZ019"},
		{"-_.~", "-_.~"}, // RFC 3986 unreserved, must stay literal
		{"a b", "a%20b"}, // space is %20, never '+'
		{"*", "%2A"},
		{"/", "%2F"},
		{"=", "%3D"},
		{"&", "%26"},
		{"_acme-challenge", "_acme-challenge"},
		{"中", "%E4%B8%AD"}, // encoded per UTF-8 byte, uppercase hex
	}
	for _, tt := range tests {
		if got := acs3PercentEncode(tt.in); got != tt.want {
			t.Errorf("acs3PercentEncode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestACS3CanonicalQuerySortsByKey(t *testing.T) {
	got := acs3CanonicalQuery(map[string]string{
		"Zebra":      "1",
		"Apple":      "2",
		"Middle":     "3",
		"DomainName": "example.com",
	})
	want := "Apple=2&DomainName=example.com&Middle=3&Zebra=1"
	if got != want {
		t.Errorf("acs3CanonicalQuery = %q, want %q", got, want)
	}
}

func TestACS3CanonicalQueryEncodesValues(t *testing.T) {
	got := acs3CanonicalQuery(map[string]string{"Value": "a b/c"})
	want := "Value=a%20b%2Fc"
	if got != want {
		t.Errorf("acs3CanonicalQuery = %q, want %q", got, want)
	}
}

func TestACS3SignedQueryMatchesCanonicalQuery(t *testing.T) {
	// 发送的 URL 查询串必须与签名时的字符串完全一致。用
	// url.Values.Encode() 构造 URL 会把空格编成 '+'，签名立即失效——
	// sign() 因此把查询串一并返回，调用方直接用它拼 URL。
	req := officialExample
	req.Params = map[string]string{"RR": "a b", "Type": "TXT"}
	_, query, _ := req.sign()
	if query != req.canonicalQueryString() {
		t.Errorf("sign() query = %q, want it identical to the signed canonical query %q",
			query, req.canonicalQueryString())
	}
	if strings.Contains(query, "+") {
		t.Errorf("query = %q, must encode space as %%20 not '+'", query)
	}
}

func TestACS3SignHeadersAreComplete(t *testing.T) {
	_, _, headers := officialExample.sign()
	for _, want := range []string{
		"Authorization", "host", "x-acs-action", "x-acs-content-sha256",
		"x-acs-date", "x-acs-signature-nonce", "x-acs-version",
	} {
		if _, ok := headers[want]; !ok {
			t.Errorf("headers missing %q; got %v", want, headers)
		}
	}
}

func TestACS3DifferentSecretGivesDifferentSignature(t *testing.T) {
	other := officialExample
	other.AccessKeySecret = "AnotherSecret"
	a, _, _ := officialExample.sign()
	b, _, _ := other.sign()
	if a == b {
		t.Error("changing the secret did not change the signature")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/dns/ -run ACS3 -v`
Expected: 编译失败，`undefined: acs3Request`

- [ ] **Step 3: 实现 acs3.go**

`internal/dns/acs3.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
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

// acs3Request carries everything the signature covers.
type acs3Request struct {
	AccessKeyID     string
	AccessKeySecret string
	Host            string
	Action          string
	Version         string
	Date            string // UTC, "2006-01-02T15:04:05Z"
	Nonce           string
	Params          map[string]string
}

// acs3PercentEncode encodes per RFC 3986: A-Z a-z 0-9 - _ . ~ stay
// literal, every other byte becomes uppercase %XX. Multi-byte UTF-8 is
// encoded byte by byte, and a space becomes %20 — not '+', which would
// invalidate the signature.
func acs3PercentEncode(s string) string {
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

// acs3CanonicalQuery joins the parameters sorted by key.
func acs3CanonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, acs3PercentEncode(k)+"="+acs3PercentEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

func (r acs3Request) canonicalQueryString() string {
	return acs3CanonicalQuery(r.Params)
}

// signedHeaders returns the headers covered by the signature, sorted by
// lowercase name.
func (r acs3Request) signedHeaders() ([]string, map[string]string) {
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

func (r acs3Request) canonicalRequest() string {
	names, headers := r.signedHeaders()
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n)
		ch.WriteString(":")
		ch.WriteString(strings.TrimSpace(headers[n]))
		ch.WriteString("\n")
	}
	// CanonicalHeaders already ends in \n, so the extra \n below produces
	// the blank line the specification requires before SignedHeaders.
	return "POST\n/\n" + r.canonicalQueryString() + "\n" +
		ch.String() + "\n" +
		strings.Join(names, ";") + "\n" +
		acs3EmptyBodySHA256
}

func (r acs3Request) stringToSign() string {
	sum := sha256.Sum256([]byte(r.canonicalRequest()))
	return acs3Algorithm + "\n" + hex.EncodeToString(sum[:])
}

// sign returns the Authorization header value, the exact query string that
// was signed, and every header to send.
//
// The query string is returned rather than rebuilt by the caller because
// the transmitted URL must be byte-identical to the signed one.
func (r acs3Request) sign() (string, string, map[string]string) {
	names, headers := r.signedHeaders()

	mac := hmac.New(sha256.New, []byte(r.AccessKeySecret))
	mac.Write([]byte(r.stringToSign()))
	signature := hex.EncodeToString(mac.Sum(nil))

	// No space after the commas — the format is exact.
	authorization := fmt.Sprintf("%s Credential=%s,SignedHeaders=%s,Signature=%s",
		acs3Algorithm, r.AccessKeyID, strings.Join(names, ";"), signature)

	out := make(map[string]string, len(headers)+1)
	for k, v := range headers {
		out[k] = v
	}
	out["Authorization"] = authorization

	return authorization, r.canonicalQueryString(), out
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/dns/ -run ACS3 -v`
Expected: 全部 PASS。若 `TestACS3CanonicalRequestMatchesOfficialExample` 失败，逐行 diff 输出——最常见的错因是 CanonicalHeaders 与 SignedHeaders 之间少了那个空行。

- [ ] **Step 5: 提交**

```bash
git add internal/dns/acs3.go internal/dns/acs3_test.go
git commit -m "feat(dns): Aliyun ACS3-HMAC-SHA256 request signing"
```

---

### Task 4: 阿里云 AliDNS provider

**Files:**
- Create: `internal/dns/aliyun.go`
- Modify: `internal/dns/provider.go`（删除 `newAliyun` 桩）
- Test: `internal/dns/aliyun_test.go`

**Interfaces:**
- Consumes: `acs3Request`（Task 3）、`Provider`/`decodeConfig`/`requireFields`/`httpClient`（Task 1）
- Produces:
  - `type aliyun struct { keyID, keySecret, domain, endpoint string; now func() time.Time; nonce func() string }`
  - `func newAliyun(configJSON string) (Provider, error)`
  - `func (a *aliyun) recordRR(fqdn string) (string, error)`
  - `const aliyunEndpoint = "https://alidns.aliyuncs.com"`、`const aliyunAPIVersion = "2015-01-09"`

`now`/`nonce` 是可注入的函数字段：签名含时间戳与随机数，测试需要固定它们才能断言。

- [ ] **Step 1: 写失败的测试**

`internal/dns/aliyun_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newAliyunWith(t *testing.T, endpoint, domain string) *aliyun {
	t.Helper()
	return &aliyun{
		keyID:     "test-key",
		keySecret: "test-secret",
		domain:    domain,
		endpoint:  endpoint,
		now:       func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		nonce:     func() string { return "fixed-nonce" },
	}
}

func TestAliyunRecordRR(t *testing.T) {
	tests := []struct {
		name, domain, fqdn, want string
		wantErr                  bool
	}{
		{"子域", "example.com", "_acme-challenge.sub.example.com", "_acme-challenge.sub", false},
		{"顶级域本身", "example.com", "_acme-challenge.example.com", "_acme-challenge", false},
		{"多级配置域", "sub.example.com", "_acme-challenge.sub.example.com", "_acme-challenge", false},
		{"后缀不匹配必须报错", "example.com", "_acme-challenge.other.com", "", true},
		{"仅部分匹配也要报错", "example.com", "_acme-challenge.notexample.com", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newAliyunWith(t, "http://unused", tt.domain)
			got, err := a.recordRR(tt.fqdn)
			if tt.wantErr {
				// Rust 版在这里静默用整个 FQDN 当 RR，于是在错误的 zone 里
				// 建出 "_acme-challenge.other.com"，验证莫名失败。
				if err == nil {
					t.Fatalf("recordRR(%q) with domain %q = %q, nil; want an error",
						tt.fqdn, tt.domain, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("recordRR() = %v", err)
			}
			if got != tt.want {
				t.Errorf("recordRR(%q) = %q, want %q", tt.fqdn, got, tt.want)
			}
		})
	}
}

func TestAliyunAddTXT(t *testing.T) {
	var gotQuery url.Values
	var gotRawQuery, gotAuth, gotDate, gotNonce, gotAction string
	var gotBodyLen int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		gotQuery = r.URL.Query()
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("x-acs-date")
		gotNonce = r.Header.Get("x-acs-signature-nonce")
		gotAction = r.Header.Get("x-acs-action")
		gotBodyLen = r.ContentLength
		w.Write([]byte(`{"RecordId":"123","RequestId":"abc"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Fatalf("AddTXT() = %v", err)
	}

	if gotAction != "AddDomainRecord" {
		t.Errorf("x-acs-action = %q, want AddDomainRecord", gotAction)
	}
	if gotQuery.Get("DomainName") != "example.com" {
		t.Errorf("DomainName = %q", gotQuery.Get("DomainName"))
	}
	if gotQuery.Get("RR") != "_acme-challenge" {
		t.Errorf("RR = %q, want _acme-challenge", gotQuery.Get("RR"))
	}
	if gotQuery.Get("Type") != "TXT" {
		t.Errorf("Type = %q, want TXT", gotQuery.Get("Type"))
	}
	if gotQuery.Get("Value") != "digest" {
		t.Errorf("Value = %q, want digest", gotQuery.Get("Value"))
	}
	if !strings.HasPrefix(gotAuth, "ACS3-HMAC-SHA256 Credential=test-key,") {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotDate != "2023-11-14T22:13:20Z" {
		t.Errorf("x-acs-date = %q, want the injected clock's value", gotDate)
	}
	if gotNonce != "fixed-nonce" {
		t.Errorf("x-acs-signature-nonce = %q", gotNonce)
	}
	if gotBodyLen > 0 {
		t.Errorf("Content-Length = %d, want an empty body (params ride in the query)", gotBodyLen)
	}
	// 发送的查询串必须与签名的一致：参数按 key 排序、空格编成 %20。
	if strings.Contains(gotRawQuery, "+") {
		t.Errorf("raw query %q contains '+', signature would not verify", gotRawQuery)
	}
}

func TestAliyunAddTXTTreatsDuplicateAsSuccess(t *testing.T) {
	// 同 RR + 同 Value 的记录已存在，说明期望状态已达成，应视为成功。
	// Rust 版在这里会列出该 RR 下所有 TXT 记录并全部删除后重试——
	// 那会连带删掉 apex/通配符场景下兄弟挑战的记录。
	var deleteCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "AddDomainRecord":
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"Code":"DomainRecordDuplicate","Message":"Domain record duplicate"}`))
		case "DeleteDomainRecord":
			deleteCalls++
			w.Write([]byte(`{"RequestId":"x"}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest"); err != nil {
		t.Errorf("AddTXT on DomainRecordDuplicate = %v, want nil (desired state already holds)", err)
	}
	if deleteCalls != 0 {
		t.Errorf("AddTXT issued %d DELETEs, want 0 — deleting would destroy a sibling challenge", deleteCalls)
	}
}

func TestAliyunAddTXTPropagatesOtherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"Code":"SignatureDoesNotMatch","Message":"signature mismatch"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "digest")
	if err == nil {
		t.Fatal("AddTXT = nil error, want failure")
	}
	if !strings.Contains(err.Error(), "SignatureDoesNotMatch") {
		t.Errorf("error = %v, want it to surface the API Code", err)
	}
}

func TestAliyunAddTXTRejectsSuccessBodyWithErrorCode(t *testing.T) {
	// 2xx 但 body 带 Code 的情况：Rust 版直接返回泛型 JSON 不做检查。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"Code":"Throttling.User","Message":"Request was denied due to user flow control"}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.example.com", "d"); err == nil {
		t.Error("AddTXT with an error Code in a 200 body = nil error, want failure")
	}
}

func TestAliyunRemoveTXTDeletesOnlyExactMatch(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "DescribeDomainRecords":
			w.Write([]byte(`{"TotalCount":3,"PageNumber":1,"PageSize":20,"DomainRecords":{"Record":[
			  {"RecordId":"want","RR":"_acme-challenge","Type":"TXT","Value":"target"},
			  {"RecordId":"other-value","RR":"_acme-challenge","Type":"TXT","Value":"sibling"},
			  {"RecordId":"other-type","RR":"_acme-challenge","Type":"A","Value":"target"}
			]}}`))
		case "DeleteDomainRecord":
			deleted = append(deleted, r.URL.Query().Get("RecordId"))
			w.Write([]byte(`{"RequestId":"x"}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "want" {
		t.Errorf("deleted = %v, want exactly [want]", deleted)
	}
}

func TestAliyunRemoveTXTPaginates(t *testing.T) {
	// AliDNS 默认每页 20 条。Rust 版不翻页，一个域名下 TXT 记录多了就
	// 漏删，challenge 记录残留。
	var pages []string
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-acs-action") {
		case "DescribeDomainRecords":
			page := r.URL.Query().Get("PageNumber")
			pages = append(pages, page)
			// TotalCount 与实际返回条数保持自洽：共 2 条、每页 1 条，
			// 于是必须取到第二页才算读完。
			if page == "1" {
				w.Write([]byte(`{"TotalCount":2,"PageNumber":1,"PageSize":1,"DomainRecords":{"Record":[
				  {"RecordId":"p1","RR":"_acme-challenge","Type":"TXT","Value":"nope"}
				]}}`))
				return
			}
			w.Write([]byte(`{"TotalCount":2,"PageNumber":2,"PageSize":1,"DomainRecords":{"Record":[
			  {"RecordId":"p2","RR":"_acme-challenge","Type":"TXT","Value":"target"}
			]}}`))
		case "DeleteDomainRecord":
			deleted = append(deleted, r.URL.Query().Get("RecordId"))
			w.Write([]byte(`{"RequestId":"x"}`))
		}
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "target"); err != nil {
		t.Fatalf("RemoveTXT() = %v", err)
	}
	if len(pages) < 2 {
		t.Errorf("requested pages = %v, want it to fetch beyond page 1", pages)
	}
	if len(deleted) != 1 || deleted[0] != "p2" {
		t.Errorf("deleted = %v, want [p2] from the second page", deleted)
	}
}

func TestAliyunRemoveTXTIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"TotalCount":0,"PageNumber":1,"PageSize":20,"DomainRecords":{"Record":[]}}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.RemoveTXT(context.Background(), "_acme-challenge.example.com", "gone"); err != nil {
		t.Errorf("RemoveTXT with no matching record = %v, want nil", err)
	}
}

func TestAliyunRejectsRRMismatchBeforeCallingAPI(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	a := newAliyunWith(t, srv.URL, "example.com")
	if err := a.AddTXT(context.Background(), "_acme-challenge.other.com", "d"); err == nil {
		t.Error("AddTXT with a mismatched zone = nil error, want failure")
	}
	if called {
		t.Error("AddTXT called the API despite the zone mismatch")
	}
}

func TestNewAcceptsValidConfig(t *testing.T) {
	// 正向用例放在这里而不是 Task 1：两个 provider 都实现之后，
	// New 才真的能返回可用实例。
	tests := []struct{ kind, config string }{
		{KindCloudflare, `{"api_token":"t","zone_id":"z"}`},
		{KindAliyun, `{"access_key_id":"k","access_key_secret":"s","domain":"example.com"}`},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			p, err := New(tt.kind, tt.config)
			if err != nil {
				t.Fatalf("New = %v", err)
			}
			if p == nil {
				t.Fatal("New returned a nil Provider with no error")
			}
		})
	}
}

func TestNewAliyunUsesRealEndpointByDefault(t *testing.T) {
	p, err := newAliyun(`{"access_key_id":"k","access_key_secret":"s","domain":"example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := p.(*aliyun)
	if !ok {
		t.Fatalf("newAliyun returned %T, want *aliyun", p)
	}
	if a.endpoint != aliyunEndpoint {
		t.Errorf("endpoint = %q, want %q", a.endpoint, aliyunEndpoint)
	}
	if a.now == nil || a.nonce == nil {
		t.Error("now/nonce must be populated so signing works outside tests")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/dns/ -run Aliyun -v`
Expected: 编译失败，`undefined: aliyun`

- [ ] **Step 3: 实现 aliyun.go**

`internal/dns/aliyun.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
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
		nonce:     randomNonce,
	}, nil
}

func randomNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is fatal for signing; fall back to the clock
		// so the request fails at the API rather than panicking here.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
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

	req := acs3Request{
		AccessKeyID:     a.keyID,
		AccessKeySecret: a.keySecret,
		Host:            host,
		Action:          action,
		Version:         aliyunAPIVersion,
		Date:            a.now().UTC().Format("2006-01-02T15:04:05Z"),
		Nonce:           a.nonce(),
		Params:          params,
	}
	_, query, headers := req.sign()

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
			"DomainName":   a.domain,
			"RRKeyWord":    rr,
			"TypeKeyWord":  "TXT",
			"PageNumber":   strconv.Itoa(page),
			"PageSize":     strconv.Itoa(aliyunPageSize),
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
```

- [ ] **Step 4: 删掉 Task 1 的阿里云桩**

从 `internal/dns/provider.go` 末尾删除标注"临时桩，Task 4 替换"的 `newAliyun` 函数。此时 `provider.go` 里应已无任何桩。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/dns/ -v && go vet ./...`
Expected: 全部 PASS，包括本任务新增的 `TestNewAcceptsValidConfig`。

注意 `TestAliyunAddTXT` 断言 `x-acs-date` 为 `2023-11-14T22:13:20Z`——那是注入时钟 `time.Unix(1_700_000_000, 0).UTC()` 的值。若断言失败先确认时钟注入生效，不要改期望值。

- [ ] **Step 6: 提交**

```bash
git add internal/dns/
git commit -m "feat(dns): Aliyun AliDNS provider with pagination and zone validation"
```

---

### Task 5: DoH 传播校验

**Files:**
- Create: `internal/dns/doh.go`
- Test: `internal/dns/doh_test.go`

**Interfaces:**
- Consumes: 无（用独立的 client，因为超时诉求不同）
- Produces:
  - `type Verifier struct { Server string; MaxRetries int; Interval time.Duration; client *http.Client }`
  - `func NewVerifier(server string, maxRetries int, interval time.Duration) *Verifier`
  - `func (v *Verifier) Wait(ctx context.Context, name, value string) error` — 轮询直到 TXT 可见或次数耗尽
  - `func (v *Verifier) lookup(ctx context.Context, name, value string) (bool, error)` — 单次查询
  - `const DefaultDoHServer = "https://cloudflare-dns.com/dns-query"`、`const DefaultInterval = 5 * time.Second`

- [ ] **Step 1: 写失败的测试**

`internal/dns/doh_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifierLookupMatches(t *testing.T) {
	var gotName, gotType, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotName = r.URL.Query().Get("name")
		gotType = r.URL.Query().Get("type")
		gotAccept = r.Header.Get("Accept")
		w.Write([]byte(`{"Status":0,"Answer":[{"name":"_acme-challenge.example.com","type":16,"data":"\"the-digest\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 1, time.Millisecond)
	ok, err := v.lookup(context.Background(), "_acme-challenge.example.com", "the-digest")
	if err != nil {
		t.Fatalf("lookup() = %v", err)
	}
	if !ok {
		t.Error("lookup() = false, want true")
	}
	if gotName != "_acme-challenge.example.com" {
		t.Errorf("name = %q", gotName)
	}
	if gotType != "TXT" {
		t.Errorf("type = %q, want TXT", gotType)
	}
	if gotAccept != "application/dns-json" {
		t.Errorf("Accept = %q, want application/dns-json", gotAccept)
	}
}

func TestVerifierLookupStripsQuotes(t *testing.T) {
	tests := []struct {
		name, data, want string
		match            bool
	}{
		{"带引号", `"digest"`, "digest", true},
		{"不带引号", `digest`, "digest", true},
		{"值不同", `"other"`, "digest", false},
		{"多段拼接的长 TXT", `"part-one" "part-two"`, "part-onepart-two", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"Status":0,"Answer":[{"data":` + jsonQuote(tt.data) + `}]}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			}))
			defer srv.Close()

			v := NewVerifier(srv.URL, 1, time.Millisecond)
			ok, err := v.lookup(context.Background(), "n", tt.want)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tt.match {
				t.Errorf("lookup() = %v, want %v (data %q, expected %q)", ok, tt.match, tt.data, tt.want)
			}
		})
	}
}

func TestVerifierNXDOMAINIsNotAnError(t *testing.T) {
	// 记录刚建好、还没传播时权威服务器会回 NXDOMAIN。这是"再等等"，
	// 不是错误——当成错误会让签发在第一次查询就失败。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":3}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 1, time.Millisecond)
	ok, err := v.lookup(context.Background(), "n", "v")
	if err != nil {
		t.Errorf("lookup() on NXDOMAIN = %v, want nil error", err)
	}
	if ok {
		t.Error("lookup() = true on NXDOMAIN, want false")
	}
}

func TestVerifierWaitRetriesUntilVisible(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.Write([]byte(`{"Status":0,"Answer":[]}`))
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 5, time.Millisecond)
	if err := v.Wait(context.Background(), "n", "v"); err != nil {
		t.Fatalf("Wait() = %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("queries = %d, want 3 (stops as soon as the record is visible)", got)
	}
}

func TestVerifierWaitExhaustsRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"Status":0,"Answer":[]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 3, time.Millisecond)
	err := v.Wait(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil {
		t.Fatal("Wait() = nil error, want a timeout after the retries run out")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("queries = %d, want exactly 3", got)
	}
}

func TestVerifierWaitHonoursContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Status":0,"Answer":[]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	v := NewVerifier(srv.URL, 100, time.Hour)
	start := time.Now()
	if err := v.Wait(ctx, "n", "v"); err == nil {
		t.Error("Wait() with a cancelled context = nil error, want failure")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Wait() took %v; a cancelled context must not sleep through the interval", elapsed)
	}
}

func TestVerifierTransportErrorCountsAsRetry(t *testing.T) {
	// DoH 服务器抖动不应直接判定签发失败，只算一次失败尝试。
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Write([]byte(`{"Status":0,"Answer":[{"data":"\"v\""}]}`))
	}))
	defer srv.Close()

	v := NewVerifier(srv.URL, 4, time.Millisecond)
	if err := v.Wait(context.Background(), "n", "v"); err != nil {
		t.Errorf("Wait() = %v, want it to ride out a transient 502", err)
	}
}

func TestNewVerifierDefaults(t *testing.T) {
	v := NewVerifier("", 0, 0)
	if v.Server != DefaultDoHServer {
		t.Errorf("Server = %q, want %q", v.Server, DefaultDoHServer)
	}
	if v.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", v.MaxRetries, DefaultMaxRetries)
	}
	if v.Interval != DefaultInterval {
		t.Errorf("Interval = %v, want %v", v.Interval, DefaultInterval)
	}
	if v.client == nil || v.client.Timeout == 0 {
		t.Error("the DoH client must have a timeout; the Rust implementation had none")
	}
}

// jsonQuote 把字符串编码成 JSON 字面量，供表驱动构造响应体。
func jsonQuote(s string) string {
	var b []byte
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			b = append(b, '\\')
		}
		b = append(b, s[i])
	}
	return string(append(b, '"'))
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/dns/ -run Verifier -v`
Expected: 编译失败，`undefined: NewVerifier`

- [ ] **Step 3: 实现 doh.go**

`internal/dns/doh.go`：

```go
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
	"net/url"
	"strings"
	"time"
)

// Defaults for propagation checking.
const (
	DefaultDoHServer  = "https://cloudflare-dns.com/dns-query"
	DefaultMaxRetries = 12
	DefaultInterval   = 5 * time.Second

	// dohNXDOMAIN is RCODE 3: the name does not exist yet, which during
	// propagation means "not visible", not "broken".
	dohNXDOMAIN = 3
)

// Verifier polls a DNS-over-HTTPS resolver until a challenge TXT record is
// visible. Checking propagation before telling the CA the challenge is
// ready avoids burning an ACME validation attempt on a record the
// authoritative servers have not picked up.
type Verifier struct {
	Server     string
	MaxRetries int
	Interval   time.Duration

	client *http.Client
}

func NewVerifier(server string, maxRetries int, interval time.Duration) *Verifier {
	if server == "" {
		server = DefaultDoHServer
	}
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Verifier{
		Server:     server,
		MaxRetries: maxRetries,
		Interval:   interval,
		// The Rust implementation set no timeout, so a stalled resolver
		// hung the whole issuance.
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Wait polls until the record is visible or the retries run out. A query
// error counts as a failed attempt rather than aborting: resolvers are
// flaky and an issuance should ride out a transient failure.
func (v *Verifier) Wait(ctx context.Context, name, value string) error {
	var lastErr error
	for attempt := 1; attempt <= v.MaxRetries; attempt++ {
		ok, err := v.lookup(ctx, name, value)
		if err == nil && ok {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
		}
		if attempt == v.MaxRetries {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(v.Interval):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("TXT record %q did not become visible after %d attempts (last error: %w)",
			name, v.MaxRetries, lastErr)
	}
	return fmt.Errorf("TXT record %q did not become visible after %d attempts", name, v.MaxRetries)
}

// dohResponse is the application/dns-json answer shape.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// lookup performs one DoH query, reporting whether the expected value is
// present.
func (v *Verifier) lookup(ctx context.Context, name, value string) (bool, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("type", "TXT")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Server+"?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, fmt.Errorf("DoH query failed: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 500))
	}

	var answer dohResponse
	if err := json.Unmarshal(raw, &answer); err != nil {
		return false, fmt.Errorf("DoH query returned malformed JSON: %w", err)
	}
	if answer.Status == dohNXDOMAIN {
		return false, nil
	}
	for _, a := range answer.Answer {
		if normalizeTXT(a.Data) == value {
			return true, nil
		}
	}
	return false, nil
}

// normalizeTXT reassembles a TXT value as the resolver reports it. Strings
// longer than 255 bytes arrive split into several quoted segments, so the
// quotes are removed and the segments concatenated rather than merely
// trimming the outer quotes — which is why the Rust implementation could
// fail to match a long record.
func normalizeTXT(data string) string {
	if !strings.Contains(data, `"`) {
		return strings.TrimSpace(data)
	}
	var b strings.Builder
	inQuotes := false
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == '\\' && i+1 < len(data):
			i++
			b.WriteByte(data[i])
		case data[i] == '"':
			inQuotes = !inQuotes
		case inQuotes:
			b.WriteByte(data[i])
		}
	}
	return b.String()
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/dns/ -v && go vet ./... && CGO_ENABLED=0 go build ./...`
Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
git add internal/dns/
git commit -m "feat(dns): DoH propagation verification with retries"
```

---

## 完成标准

- `go build ./... && go test ./... && go vet ./...` 全绿，`CGO_ENABLED=0` 可编译。
- `internal/dns` 提供 `Provider` 接口、两个实现、以及 `Verifier`。
- 阿里云签名与官方文档算例逐字节一致（`TestACS3SignatureMatchesOfficialExample`）。
- 三处刻意行为差异各有回归测试：Cloudflare 不再先删（`TestCloudflareAddTXTDoesNotDeleteFirst`）、检查 `success`（`TestCloudflareAddTXTRejectsSuccessFalse`）、阿里云 zone 不匹配报错（`TestAliyunRecordRR`）。
- 每个出网 HTTP 客户端都有超时。
- 未引入任何云厂商 SDK：`go list -deps ./internal/dns | grep -iE 'aliyun|alibaba|cloudflare'` 应无输出。

## 交接给里程碑 2b 的接口

- `dns.New(kind, configJSON) (Provider, error)`、`dns.Provider`、`dns.Kinds()`
- `dns.NewVerifier(server, maxRetries, interval) *Verifier`、`(*Verifier).Wait(ctx, name, value) error`

2b 的 acmez solver 在 `Present()` 里调 `Provider.AddTXT`、`Wait()` 里调 `Verifier.Wait`、`CleanUp()` 里调 `Provider.RemoveTXT`。`Verifier` 的三个参数由 `config.DoHServer()`、`config.DNSMaxRetries()` 与 `dns.DefaultInterval` 提供。
