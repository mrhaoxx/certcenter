# CertCenter Go 重写 — 里程碑 2b：ACME 账户与签发引擎 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让证书真的能签出来——ACME 账户注册/导入、自驱的签发状态机、逐步落库的事件时间线，并用进程内的 Pebble 测试 CA 做端到端验证。

**Architecture:** `internal/issuance` 用 acmez 的**低层 `acme.Client`** 自己驱动 ACME 状态机（`NewOrder` → `GetAuthorization` → 写 TXT → 等传播 → `InitiateChallenge` → `PollAuthorization` → `FinalizeOrder` → `GetCertificateChain`），每一步前后往 `events` 表写一条记录。DNS 侧直接调用里程碑 2a 的 `dns.Provider` 与 `dns.Verifier`。`internal/db` 扩出账户、证书、运行记录与事件的方法。

**Tech Stack:** Go 1.26、`github.com/mholt/acmez/v3`（低层 `acme` 包 + `NewCSR`）、标准库 `crypto/x509`、测试用 `github.com/letsencrypt/pebble/v2` + `github.com/letsencrypt/challtestsrv`。

设计依据：规范 `docs/superpowers/specs/2026-07-26-certcenter-go-rewrite-design.md` §4、§8、§14。

## Global Constraints

- 模块路径 `github.com/mrhaoxx/certcenter`，Go 1.26。每个新 `.go` 文件以这三行开头，一字不差：
  ```go
  // Copyright 2026 The CertCenter Authors.
  //
  // SPDX-License-Identifier: Apache-2.0
  ```
- **必须用低层 `acme.Client` 自驱状态机**，不得改用 `acmez.Client.ObtainCertificate*`。高层 API 把整个流程包在一次调用里，事件时间线就只剩"开始"和"结束"两条——而选 acmez 而非 lego 的全部理由就是这条时间线（规范 §2）。
- 账户私钥与证书私钥都以 **PKCS#8 PEM** 存储（`-----BEGIN PRIVATE KEY-----`），密钥类型 **ECDSA P-256**。
- 签发全程套 **10 分钟总超时**；每个可能阻塞的调用都吃 `context`。
- `CGO_ENABLED=0` 必须能编译（Pebble 与 challtestsrv 只在 `_test.go` 里引用，不进生产依赖图）。
- 每个任务结束时 `go build ./... && go test ./... && go vet ./...` 全绿。

## 已实证的前提（写计划前用真实代码验证过，不要再怀疑）

这些不是推断，是跑出来的结果：

1. **Pebble 能完全进程内运行**，配 `challtestsrv` 的 DNS 服务器做自定义解析器，可跑真实 DNS-01 签发，全程 0.78 秒、不出网、不需要 Docker。
2. **apex + 通配符同证书时，两个授权对同一记录名写入两个不同摘要，且必须同时存在**。实测日志里两次 `Present` 之间没有 CleanUp，两条 TXT 共存才双双验证通过。这就是里程碑 2a"纯追加"设计的实证依据。
3. **Pebble 签出的链是 2 个 PEM 块**（叶子 + 中间），叶子 `Subject` 为空，有效期恰好 **90 天**——证实规范 §14 那两条：链必须拆分、`not_after` 必须从真实证书读而不能按 `validity_days` 估算。
4. **ARI 可用**：`GetRenewalInfo` 返回约两天宽的续期窗口，位于生命周期约三分之二处。
5. **PKCS#8 PEM 往返无损**，解析回 `*ecdsa.PrivateKey`（P-256）且与原 key `Equal`。
6. **空 Subject 的 CSR 合法**，签名算法 ECDSA-SHA256，自签名校验通过。
7. **`acmez.NewCSR` 会签名并返回已解析的 CSR**，`csr.Raw` 即 `FinalizeOrder` 所需 DER；它还做 IDNA punycode 归一化，因此不要自己拼 CSR 模板。

## 相对规范的一处简化

规范 §3 列了 `internal/issuance/solver.go` 实现 `acmez.Solver`。**本计划不实现该接口**：既然状态机由我们自驱，`Present`/`Wait`/`CleanUp` 的编排就在 `issue.go` 里，直接调 `dns.Provider` 与 `dns.Verifier` 即可，多一层 `acmez.Solver` 适配没有收益。`solver.go` 因此不存在。

## 测试用假 DNS provider 的一个陷阱

`challtestsrv.DeleteDNSTXTRecord(host)` 删除该名下**全部** TXT 记录。测试的假 provider 若直接转调它，就会掩盖"`RemoveTXT` 删多了"这类 bug——而这正是里程碑 2a 修掉的缺陷类型。假 provider 必须自己维护 `map[name][]value`，按 `(name, value)` 精确删除后把幸存值重新灌回 challtestsrv。Task 4 的代码已按此实现。

---

### Task 1: Store —— ACME 账户

**Files:**
- Modify: `internal/db/store.go`（加类型与接口方法）
- Create: `internal/db/accounts.go`
- Test: `internal/db/accounts_test.go`

**Interfaces:**
- Consumes: `db.SQLite`、`db.ErrNotFound`、`NewTestDB`（里程碑 1）
- Produces:
  - `type ACMEAccount struct { ID int64; Name, DirectoryURL, Email string; AccountURL *string; PrivateKeyPEM string; ValidityDays int64; CreatedAt, UpdatedAt string }`
    - `PrivateKeyPEM` 带 `json:"-"`：账户私钥绝不出 API
  - `Store` 新增：`CreateACMEAccount`、`GetACMEAccount`、`ListACMEAccounts`、`UpdateACMEAccount`、`DeleteACMEAccount`
  - `type ACMEAccountUpdate struct { Name, Email *string; ValidityDays *int64 }`

- [ ] **Step 1: 写失败的测试**

`internal/db/accounts_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestACMEAccountRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()

	url := "https://acme.example/acct/1"
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name:          "letsencrypt",
		DirectoryURL:  "https://acme-v02.api.letsencrypt.org/directory",
		Email:         "admin@example.com",
		AccountURL:    &url,
		PrivateKeyPEM: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
		ValidityDays:  90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatal("CreateACMEAccount returned id 0")
	}

	got, err := s.GetACMEAccount(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "letsencrypt" || got.Email != "admin@example.com" {
		t.Errorf("account = %+v", got)
	}
	if got.AccountURL == nil || *got.AccountURL != url {
		t.Errorf("AccountURL = %v, want %q", got.AccountURL, url)
	}
	if !strings.Contains(got.PrivateKeyPEM, "BEGIN PRIVATE KEY") {
		t.Errorf("PrivateKeyPEM = %q, want the stored PEM", got.PrivateKeyPEM)
	}
	if got.ValidityDays != 90 {
		t.Errorf("ValidityDays = %d, want 90", got.ValidityDays)
	}
	if got.CreatedAt == "" || got.UpdatedAt == "" {
		t.Error("timestamps not populated by the DB defaults")
	}
}

func TestACMEAccountPrivateKeyNeverSerialized(t *testing.T) {
	// 账户私钥等同于对 CA 的身份凭证，任何 API 响应都不能带上它。
	raw, err := json.Marshal(ACMEAccount{
		Name:          "x",
		PrivateKeyPEM: "SUPER-SECRET-KEY-MATERIAL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SUPER-SECRET-KEY-MATERIAL") {
		t.Fatalf("marshalled account leaks the private key: %s", raw)
	}
	if strings.Contains(string(raw), "privateKey") {
		t.Errorf("marshalled account exposes a privateKey field: %s", raw)
	}
}

func TestGetACMEAccountMissing(t *testing.T) {
	s := NewTestDB(t)
	if _, err := s.GetACMEAccount(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetACMEAccount(999) = %v, want ErrNotFound", err)
	}
}

func TestListACMEAccountsNewestFirst(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	for _, n := range []string{"first", "second"} {
		if _, err := s.CreateACMEAccount(ctx, ACMEAccount{
			Name: n, DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
		}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListACMEAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "second" {
		t.Errorf("list[0].Name = %q, want %q (newest first)", list[0].Name, "second")
	}
}

func TestListACMEAccountsEmptyIsNotNil(t *testing.T) {
	s := NewTestDB(t)
	list, err := s.ListACMEAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if list == nil {
		t.Error("ListACMEAccounts returned nil, want an empty non-nil slice")
	}
}

func TestUpdateACMEAccountIsSparse(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "old", DirectoryURL: "d", Email: "old@example.com",
		PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}

	newName := "new"
	if err := s.UpdateACMEAccount(ctx, id, ACMEAccountUpdate{Name: &newName}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetACMEAccount(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "new" {
		t.Errorf("Name = %q, want new", got.Name)
	}
	if got.Email != "old@example.com" {
		t.Errorf("Email = %q, want it untouched by a name-only update", got.Email)
	}
	if got.DirectoryURL != "d" {
		t.Errorf("DirectoryURL = %q, want it immutable", got.DirectoryURL)
	}
}

func TestUpdateACMEAccountMissing(t *testing.T) {
	// UPDATE 影响 0 行在 SQLite 里不是错误，必须显式报 ErrNotFound，
	// 否则 API 会对一个不存在的 id 返回 200。
	s := NewTestDB(t)
	name := "x"
	err := s.UpdateACMEAccount(context.Background(), 999, ACMEAccountUpdate{Name: &name})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateACMEAccount(999) = %v, want ErrNotFound", err)
	}
}

func TestDeleteACMEAccount(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	id, err := s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "x", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteACMEAccount(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetACMEAccount(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("account still present after delete: %v", err)
	}
	if err := s.DeleteACMEAccount(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/db/ -run ACMEAccount -v`
Expected: 编译失败，`s.CreateACMEAccount undefined`

- [ ] **Step 3: 在 store.go 加类型与接口方法**

追加到 `internal/db/store.go`：

```go
// ACMEAccount is a registered account at a CA. JSON tags are the API shape.
type ACMEAccount struct {
	ID           int64   `json:"id"`
	Name         string  `json:"name"`
	DirectoryURL string  `json:"directoryUrl"`
	Email        string  `json:"email"`
	AccountURL   *string `json:"accountUrl"`
	// PrivateKeyPEM is the account key (PKCS#8 PEM). It is the credential
	// that authenticates us to the CA, so it never leaves the process:
	// json:"-" keeps it out of every API response.
	PrivateKeyPEM string `json:"-"`
	ValidityDays  int64  `json:"validityDays"`
	CreatedAt     string `json:"createdAt"`
	UpdatedAt     string `json:"updatedAt"`
}

// ACMEAccountUpdate is a sparse patch: nil fields are left unchanged.
// DirectoryURL and the private key are immutable — changing either would
// silently point the account at a different CA identity.
type ACMEAccountUpdate struct {
	Name         *string
	Email        *string
	ValidityDays *int64
}
```

并把这五个方法加进 `Store` 接口：

```go
	CreateACMEAccount(ctx context.Context, a ACMEAccount) (int64, error)
	GetACMEAccount(ctx context.Context, id int64) (*ACMEAccount, error)
	ListACMEAccounts(ctx context.Context) ([]ACMEAccount, error)
	UpdateACMEAccount(ctx context.Context, id int64, p ACMEAccountUpdate) error
	DeleteACMEAccount(ctx context.Context, id int64) error
```

- [ ] **Step 4: 实现 accounts.go**

`internal/db/accounts.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const acmeAccountColumns = `id, name, directory_url, email, account_url,
	private_key, validity_days, created_at, updated_at`

func scanACMEAccount(row interface{ Scan(...any) error }) (*ACMEAccount, error) {
	var a ACMEAccount
	err := row.Scan(&a.ID, &a.Name, &a.DirectoryURL, &a.Email, &a.AccountURL,
		&a.PrivateKeyPEM, &a.ValidityDays, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *SQLite) CreateACMEAccount(ctx context.Context, a ACMEAccount) (int64, error) {
	if a.ValidityDays <= 0 {
		a.ValidityDays = 90
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO acme_accounts (name, directory_url, email, account_url, private_key, validity_days)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		a.Name, a.DirectoryURL, a.Email, a.AccountURL, a.PrivateKeyPEM, a.ValidityDays)
	if err != nil {
		return 0, fmt.Errorf("create acme account: %w", err)
	}
	return res.LastInsertId()
}

func (s *SQLite) GetACMEAccount(ctx context.Context, id int64) (*ACMEAccount, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts WHERE id = ?`, id)
	a, err := scanACMEAccount(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get acme account %d: %w", id, err)
	}
	return a, nil
}

func (s *SQLite) ListACMEAccounts(ctx context.Context) ([]ACMEAccount, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+acmeAccountColumns+` FROM acme_accounts ORDER BY id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list acme accounts: %w", err)
	}
	defer rows.Close()

	out := []ACMEAccount{}
	for rows.Next() {
		a, err := scanACMEAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan acme account: %w", err)
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateACMEAccount(ctx context.Context, id int64, p ACMEAccountUpdate) error {
	sets := []string{}
	args := []any{}
	if p.Name != nil {
		sets = append(sets, "name = ?")
		args = append(args, *p.Name)
	}
	if p.Email != nil {
		sets = append(sets, "email = ?")
		args = append(args, *p.Email)
	}
	if p.ValidityDays != nil {
		sets = append(sets, "validity_days = ?")
		args = append(args, *p.ValidityDays)
	}
	if len(sets) == 0 {
		// Nothing to change, but the caller still expects a missing id to
		// be reported.
		if _, err := s.GetACMEAccount(ctx, id); err != nil {
			return err
		}
		return nil
	}
	sets = append(sets, "updated_at = datetime('now')")
	args = append(args, id)

	res, err := s.DB.ExecContext(ctx,
		`UPDATE acme_accounts SET `+joinComma(sets)+` WHERE id = ?`, args...)
	if err != nil {
		return fmt.Errorf("update acme account %d: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) DeleteACMEAccount(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM acme_accounts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete acme account %d: %w", id, err)
	}
	return requireAffected(res)
}
```

在 `internal/db/sqlite.go` 末尾加两个共用辅助（后续任务也要用）：

```go
// requireAffected turns "UPDATE/DELETE matched no rows" into ErrNotFound.
// SQLite reports success for a statement that changed nothing, so without
// this an API call against a nonexistent id would answer 200.
func requireAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// joinComma joins SQL fragments; strings.Join with an explicit import kept
// out of every query builder.
func joinComma(parts []string) string {
	return strings.Join(parts, ", ")
}
```

`sqlite.go` 的 import 补 `"strings"`。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/db/ -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 6: 提交**

```bash
git add internal/db/
git commit -m "feat(db): ACME account store"
```

---

### Task 2: Store —— 证书

**Files:**
- Modify: `internal/db/store.go`
- Create: `internal/db/certificates.go`
- Test: `internal/db/certificates_test.go`

**Interfaces:**
- Consumes: Task 1 的 `requireAffected`、`joinComma`
- Produces:
  - `type Certificate struct { ... }`（`KeyPEM` 带 `json:"-"`）
  - `Store` 新增：`CreateCertificate`、`GetCertificate`、`ListCertificates`、`UpdateCertificateStatus`、`SaveIssuedCertificate`、`DeleteCertificate`
  - `type CertificateFilter struct { Search, Status string }`
  - `type IssuedCertificate struct { CertPEM, ChainPEM, KeyPEM, Serial string; NotBefore, NotAfter time.Time; RenewAfter *time.Time }`

- [ ] **Step 1: 写失败的测试**

`internal/db/certificates_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// seedDeps 建出证书所依赖的账户与 DNS 提供商。
func seedDeps(t *testing.T, s *SQLite) (acctID, dnsID int64) {
	t.Helper()
	ctx := context.Background()
	var err error
	acctID, err = s.CreateACMEAccount(ctx, ACMEAccount{
		Name: "le", DirectoryURL: "d", Email: "e", PrivateKeyPEM: "p", ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO dns_providers (name, kind, config) VALUES ('cf','cloudflare','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err = res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return acctID, dnsID
}

func TestCertificateRoundTrip(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	id, err := s.CreateCertificate(ctx, Certificate{
		Domain:        "example.com",
		SANs:          []string{"*.example.com"},
		ACMEAccountID: acctID,
		DNSProviderID: dnsID,
		ValidityDays:  90,
		AutoRenew:     true,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain = %q", got.Domain)
	}
	if len(got.SANs) != 1 || got.SANs[0] != "*.example.com" {
		t.Errorf("SANs = %v, want [*.example.com]", got.SANs)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want pending", got.Status)
	}
	if !got.AutoRenew {
		t.Error("AutoRenew = false, want true")
	}
}

func TestCertificateEmptySANsRoundTrip(t *testing.T) {
	// SANs 存的是 JSON 数组；空列表必须回来还是空列表而不是 nil 崩溃。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "solo.example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.SANs) != 0 {
		t.Errorf("SANs = %v, want empty", got.SANs)
	}
}

func TestCertificatePrivateKeyNeverSerialized(t *testing.T) {
	raw, err := json.Marshal(Certificate{Domain: "x", KeyPEM: "SECRET-CERT-KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "SECRET-CERT-KEY") {
		t.Fatalf("marshalled certificate leaks the private key: %s", raw)
	}
}

func TestSaveIssuedCertificateStoresRealDates(t *testing.T) {
	// 规范 §14：Rust 版把 not_before/not_after 按 validity_days 估算，
	// 而 Let's Encrypt 固定签 90 天，所以 validity_days≠90 时库里就是错的，
	// 偏偏续期调度器就靠这两个值算阈值。这里必须存真实证书里的日期。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 30, AutoRenew: true, // 故意与真实 90 天不一致
	})
	if err != nil {
		t.Fatal(err)
	}

	notBefore := time.Date(2026, 7, 26, 15, 10, 17, 0, time.UTC)
	notAfter := time.Date(2026, 10, 24, 15, 10, 16, 0, time.UTC)
	renewAfter := time.Date(2026, 9, 23, 15, 10, 16, 0, time.UTC)
	err = s.SaveIssuedCertificate(ctx, id, IssuedCertificate{
		CertPEM:    "LEAF",
		ChainPEM:   "INTERMEDIATE",
		KeyPEM:     "KEY",
		Serial:     "2639836FB19994A0",
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		RenewAfter: &renewAfter,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "issued" {
		t.Errorf("Status = %q, want issued", got.Status)
	}
	if got.CertPEM == nil || *got.CertPEM != "LEAF" {
		t.Errorf("CertPEM = %v, want the leaf alone", got.CertPEM)
	}
	if got.ChainPEM == nil || *got.ChainPEM != "INTERMEDIATE" {
		t.Errorf("ChainPEM = %v, want the intermediates alone", got.ChainPEM)
	}
	if got.CertPEM != nil && got.ChainPEM != nil && *got.CertPEM == *got.ChainPEM {
		t.Error("CertPEM equals ChainPEM; the leaf was never split from the chain")
	}
	if got.NotAfter == nil || !strings.HasPrefix(*got.NotAfter, "2026-10-24") {
		t.Errorf("NotAfter = %v, want the certificate's real expiry", got.NotAfter)
	}
	if got.Serial == nil || *got.Serial != "2639836FB19994A0" {
		t.Errorf("Serial = %v", got.Serial)
	}
	if got.RenewAfter == nil || !strings.HasPrefix(*got.RenewAfter, "2026-09-23") {
		t.Errorf("RenewAfter = %v, want the ARI window start", got.RenewAfter)
	}
	if got.LastError != nil {
		t.Errorf("LastError = %v, want it cleared on success", got.LastError)
	}
	if got.RetryCount != 0 {
		t.Errorf("RetryCount = %d, want it reset on success", got.RetryCount)
	}
}

func TestUpdateCertificateStatusRecordsError(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	id, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateCertificateStatus(ctx, id, "error", "DNS verification timed out"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCertificate(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" {
		t.Errorf("Status = %q", got.Status)
	}
	if got.LastError == nil || *got.LastError != "DNS verification timed out" {
		t.Errorf("LastError = %v", got.LastError)
	}
}

func TestListCertificatesFilters(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)

	for _, c := range []struct {
		domain string
		sans   []string
		status string
	}{
		{"alpha.example.com", nil, "issued"},
		{"beta.example.com", []string{"extra.beta.com"}, "pending"},
		{"gamma.other.net", nil, "error"},
	} {
		id, err := s.CreateCertificate(ctx, Certificate{
			Domain: c.domain, SANs: c.sans, ACMEAccountID: acctID, DNSProviderID: dnsID,
			ValidityDays: 90, AutoRenew: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if c.status != "pending" {
			if err := s.UpdateCertificateStatus(ctx, id, c.status, ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	tests := []struct {
		name    string
		filter  CertificateFilter
		wantLen int
	}{
		{"无过滤", CertificateFilter{}, 3},
		{"按状态", CertificateFilter{Status: "issued"}, 1},
		{"按域名子串", CertificateFilter{Search: "example.com"}, 2},
		{"搜索命中 SAN", CertificateFilter{Search: "extra.beta"}, 1},
		{"状态与搜索同时生效", CertificateFilter{Search: "example.com", Status: "pending"}, 1},
		{"无命中", CertificateFilter{Search: "nope"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := s.ListCertificates(ctx, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if len(list) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(list), tt.wantLen)
			}
		})
	}
}

func TestDeleteCertificateMissing(t *testing.T) {
	s := NewTestDB(t)
	if err := s.DeleteCertificate(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteCertificate(999) = %v, want ErrNotFound", err)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/db/ -run Certificate -v`
Expected: 编译失败，`s.CreateCertificate undefined`

- [ ] **Step 3: 加类型到 store.go**

```go
// Certificate is one managed certificate. JSON tags are the API shape.
type Certificate struct {
	ID            int64    `json:"id"`
	Domain        string   `json:"domain"`
	SANs          []string `json:"sans"`
	ACMEAccountID int64    `json:"acmeAccountId"`
	DNSProviderID int64    `json:"dnsProviderId"`

	// CertPEM holds the leaf alone and ChainPEM the intermediates alone.
	// The Rust implementation wrote the full chain into both, so the UI
	// rendered the leaf twice and the config-center deploy pushed the
	// chain duplicated (spec §14).
	CertPEM  *string `json:"certPem"`
	ChainPEM *string `json:"chainPem"`
	// KeyPEM never leaves the process except through the bundle endpoint.
	KeyPEM string `json:"-"`

	Serial     *string `json:"serial"`
	NotBefore  *string `json:"notBefore"`
	NotAfter   *string `json:"notAfter"`
	RenewAfter *string `json:"renewAfter"`

	ValidityDays int64   `json:"validityDays"`
	Status       string  `json:"status"` // pending|issued|error|expired
	LastError    *string `json:"lastError"`
	AutoRenew    bool    `json:"autoRenew"`
	RetryCount   int64   `json:"retryCount"`
	RetryAfter   *string `json:"retryAfter"`

	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// CertificateFilter narrows a list query. Search matches the domain or any
// SAN; Status matches exactly. Empty fields are ignored.
type CertificateFilter struct {
	Search string
	Status string
}

// IssuedCertificate is what a successful issuance produces. The dates come
// from parsing the leaf, never from arithmetic on ValidityDays.
type IssuedCertificate struct {
	CertPEM   string
	ChainPEM  string
	KeyPEM    string
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	// RenewAfter is the ARI-suggested window start, nil when the CA does
	// not support ARI.
	RenewAfter *time.Time
}
```

`store.go` 的 import 补 `"time"`，并把这些加进 `Store` 接口：

```go
	CreateCertificate(ctx context.Context, c Certificate) (int64, error)
	GetCertificate(ctx context.Context, id int64) (*Certificate, error)
	ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, error)
	UpdateCertificateStatus(ctx context.Context, id int64, status, lastErr string) error
	SaveIssuedCertificate(ctx context.Context, id int64, issued IssuedCertificate) error
	DeleteCertificate(ctx context.Context, id int64) error
```

- [ ] **Step 4: 实现 certificates.go**

`internal/db/certificates.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const certificateColumns = `id, domain, sans, acme_account_id, dns_provider_id,
	cert_pem, chain_pem, key_pem, serial, not_before, not_after, renew_after,
	validity_days, status, last_error, auto_renew, retry_count, retry_after,
	created_at, updated_at`

// rfc3339 is how every timestamp column produced by the application is
// formatted. SQLite's own datetime() default uses a different layout, but
// julianday() parses both, which is what the renewal query needs.
const rfc3339 = time.RFC3339

func scanCertificate(row interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var sansJSON string
	var keyPEM sql.NullString
	err := row.Scan(&c.ID, &c.Domain, &sansJSON, &c.ACMEAccountID, &c.DNSProviderID,
		&c.CertPEM, &c.ChainPEM, &keyPEM, &c.Serial, &c.NotBefore, &c.NotAfter,
		&c.RenewAfter, &c.ValidityDays, &c.Status, &c.LastError, &c.AutoRenew,
		&c.RetryCount, &c.RetryAfter, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c.KeyPEM = keyPEM.String
	c.SANs = []string{}
	if sansJSON != "" {
		if err := json.Unmarshal([]byte(sansJSON), &c.SANs); err != nil {
			return nil, fmt.Errorf("certificate %d has malformed sans: %w", c.ID, err)
		}
		if c.SANs == nil {
			c.SANs = []string{}
		}
	}
	return &c, nil
}

func (s *SQLite) CreateCertificate(ctx context.Context, c Certificate) (int64, error) {
	if c.ValidityDays <= 0 {
		c.ValidityDays = 90
	}
	sans := c.SANs
	if sans == nil {
		sans = []string{}
	}
	encoded, err := json.Marshal(sans)
	if err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO certificates (domain, sans, acme_account_id, dns_provider_id,
			validity_days, auto_renew)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		c.Domain, string(encoded), c.ACMEAccountID, c.DNSProviderID,
		c.ValidityDays, c.AutoRenew)
	if err != nil {
		return 0, fmt.Errorf("create certificate: %w", err)
	}
	return res.LastInsertId()
}

func (s *SQLite) GetCertificate(ctx context.Context, id int64) (*Certificate, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT `+certificateColumns+` FROM certificates WHERE id = ?`, id)
	c, err := scanCertificate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get certificate %d: %w", id, err)
	}
	return c, nil
}

func (s *SQLite) ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, error) {
	query := `SELECT ` + certificateColumns + ` FROM certificates WHERE 1=1`
	args := []any{}
	if f.Search != "" {
		query += ` AND (domain LIKE ? OR sans LIKE ?)`
		like := "%" + f.Search + "%"
		args = append(args, like, like)
	}
	if f.Status != "" {
		query += ` AND status = ?`
		args = append(args, f.Status)
	}
	query += ` ORDER BY id DESC`

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	defer rows.Close()

	out := []Certificate{}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, fmt.Errorf("scan certificate: %w", err)
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateCertificateStatus(ctx context.Context, id int64, status, lastErr string) error {
	var errValue any
	if lastErr != "" {
		errValue = lastErr
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET status = ?, last_error = ?, updated_at = datetime('now')
		 WHERE id = ?`, status, errValue, id)
	if err != nil {
		return fmt.Errorf("update certificate %d status: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) SaveIssuedCertificate(ctx context.Context, id int64, issued IssuedCertificate) error {
	var renewAfter any
	if issued.RenewAfter != nil {
		renewAfter = issued.RenewAfter.UTC().Format(rfc3339)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE certificates SET
			cert_pem = ?, chain_pem = ?, key_pem = ?, serial = ?,
			not_before = ?, not_after = ?, renew_after = ?,
			status = 'issued', last_error = NULL,
			retry_count = 0, retry_after = NULL,
			updated_at = datetime('now')
		 WHERE id = ?`,
		issued.CertPEM, issued.ChainPEM, issued.KeyPEM, issued.Serial,
		issued.NotBefore.UTC().Format(rfc3339), issued.NotAfter.UTC().Format(rfc3339),
		renewAfter, id)
	if err != nil {
		return fmt.Errorf("save issued certificate %d: %w", id, err)
	}
	return requireAffected(res)
}

func (s *SQLite) DeleteCertificate(ctx context.Context, id int64) error {
	// runs/events/deployments cascade via the schema's foreign keys, which
	// are enabled by the DSN.
	res, err := s.DB.ExecContext(ctx, `DELETE FROM certificates WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete certificate %d: %w", id, err)
	}
	return requireAffected(res)
}
```

import 只需 `context`、`database/sql`、`encoding/json`、`errors`、`fmt`、`time`——**不要 import `strings`**，这个文件用不到它。

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/db/ -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 6: 提交**

```bash
git add internal/db/
git commit -m "feat(db): certificate store with leaf/chain separation"
```

---

### Task 3: Store —— 运行记录、事件与 RunRecorder

这是修掉规范 §14 头号缺陷（事件时间线是死代码）的落点。

**Files:**
- Modify: `internal/db/store.go`
- Create: `internal/db/runs.go`
- Test: `internal/db/runs_test.go`

**Interfaces:**
- Produces:
  - `type Run struct { ID int64; Kind string; CertificateID int64; DeploymentID *int64; Attempt int64; Trigger, Status string; Error *string; StartedAt string; FinishedAt *string }`
  - `type Event struct { ID, RunID, Seq int64; Type, Message string; Detail *string; Level, At string }`
  - `Store` 新增：`StartRun`、`FinishRun`、`AppendEvent`、`ListRuns`、`ListRunEvents`
  - 常量：`RunKindIssue = "issue"`、`RunKindDeploy = "deploy"`、`LevelInfo/LevelSuccess/LevelError`、`RunStatusRunning/Success/Error`

- [ ] **Step 1: 写失败的测试**

`internal/db/runs_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"testing"
)

func TestStartRunAssignsIncrementingAttempt(t *testing.T) {
	// 同一张证书反复签发时，attempt 必须自增，UI 才能按次折叠时间线。
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, err := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	for want := int64(1); want <= 3; want++ {
		run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
		if err != nil {
			t.Fatal(err)
		}
		if run.Attempt != want {
			t.Errorf("attempt = %d, want %d", run.Attempt, want)
		}
		if run.Status != RunStatusRunning {
			t.Errorf("status = %q, want %q", run.Status, RunStatusRunning)
		}
	}
}

func TestAppendEventSequencesMonotonically(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "example.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err != nil {
		t.Fatal(err)
	}

	detail := "Domains: example.com"
	for _, e := range []Event{
		{Type: "start", Message: "Starting issuance", Detail: &detail, Level: LevelInfo},
		{Type: "acme_connect", Message: "Connected", Level: LevelSuccess},
		{Type: "complete", Message: "Issued", Level: LevelSuccess},
	} {
		if err := s.AppendEvent(ctx, run.ID, e); err != nil {
			t.Fatal(err)
		}
	}

	events, err := s.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("len = %d, want 3", len(events))
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}
	if events[0].Type != "start" {
		t.Errorf("events[0].Type = %q, want start (ascending order)", events[0].Type)
	}
	if events[0].Detail == nil || *events[0].Detail != detail {
		t.Errorf("events[0].Detail = %v, want %q", events[0].Detail, detail)
	}
	if events[1].Detail != nil {
		t.Errorf("events[1].Detail = %v, want nil", events[1].Detail)
	}
	if events[0].At == "" {
		t.Error("At not populated by the DB default")
	}
}

func TestAppendEventDefaultsLevel(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	run, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "auto")

	if err := s.AppendEvent(ctx, run.ID, Event{Type: "t", Message: "m"}); err != nil {
		t.Fatal(err)
	}
	events, err := s.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("len = %d, want 1", len(events))
	}
	if events[0].Level != LevelInfo {
		t.Errorf("level = %q, want %q", events[0].Level, LevelInfo)
	}
}

func TestFinishRun(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})

	tests := []struct {
		name, status, errMsg string
		wantErrStored        bool
	}{
		{"成功收尾", RunStatusSuccess, "", false},
		{"失败收尾带错误", RunStatusError, "DNS timed out", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, err := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.FinishRun(ctx, run.ID, tt.status, tt.errMsg); err != nil {
				t.Fatal(err)
			}
			runs, err := s.ListRuns(ctx, certID)
			if err != nil {
				t.Fatal(err)
			}
			// 最新的 run 在最前。
			got := runs[0]
			if got.Status != tt.status {
				t.Errorf("Status = %q, want %q", got.Status, tt.status)
			}
			if got.FinishedAt == nil {
				t.Error("FinishedAt is nil, want it set")
			}
			if tt.wantErrStored && (got.Error == nil || *got.Error != tt.errMsg) {
				t.Errorf("Error = %v, want %q", got.Error, tt.errMsg)
			}
			if !tt.wantErrStored && got.Error != nil {
				t.Errorf("Error = %v, want nil", got.Error)
			}
		})
	}
}

func TestListRunsNewestFirst(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	first, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	second, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "auto")

	runs, err := s.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("len = %d, want 2", len(runs))
	}
	if runs[0].ID != second.ID || runs[1].ID != first.ID {
		t.Errorf("order = [%d %d], want [%d %d] (newest first)",
			runs[0].ID, runs[1].ID, second.ID, first.ID)
	}
	if runs[0].Trigger != "auto" {
		t.Errorf("Trigger = %q, want auto", runs[0].Trigger)
	}
}

func TestEventsCascadeWithRun(t *testing.T) {
	s := NewTestDB(t)
	ctx := context.Background()
	acctID, dnsID := seedDeps(t, s)
	certID, _ := s.CreateCertificate(ctx, Certificate{
		Domain: "e.com", ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	run, _ := s.StartRun(ctx, RunKindIssue, certID, nil, "manual")
	if err := s.AppendEvent(ctx, run.ID, Event{Type: "t", Message: "m"}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteCertificate(ctx, certID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.DB.QueryRow("SELECT count(*) FROM events").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("events left after deleting the certificate: %d, want 0", n)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/db/ -run 'Run|Event' -v`
Expected: 编译失败，`undefined: RunKindIssue`

- [ ] **Step 3: 加类型到 store.go**

```go
// Run kinds, statuses, and event levels. These strings reach the API and
// the UI, so they are a contract.
const (
	RunKindIssue  = "issue"
	RunKindDeploy = "deploy"

	RunStatusRunning = "running"
	RunStatusSuccess = "success"
	RunStatusError   = "error"

	LevelInfo    = "info"
	LevelSuccess = "success"
	LevelError   = "error"
)

// Run is one issuance or one deployment attempt.
type Run struct {
	ID            int64   `json:"id"`
	Kind          string  `json:"kind"`
	CertificateID int64   `json:"certificateId"`
	DeploymentID  *int64  `json:"deploymentId"`
	Attempt       int64   `json:"attempt"`
	Trigger       string  `json:"trigger"` // manual|auto|api|bus
	Status        string  `json:"status"`
	Error         *string `json:"error"`
	StartedAt     string  `json:"startedAt"`
	FinishedAt    *string `json:"finishedAt"`
}

// Event is one entry of a run's timeline. Seq is assigned by AppendEvent so
// the UI can order entries that share a timestamp.
type Event struct {
	ID      int64   `json:"id"`
	RunID   int64   `json:"runId"`
	Seq     int64   `json:"seq"`
	Type    string  `json:"type"`
	Message string  `json:"message"`
	Detail  *string `json:"detail"`
	Level   string  `json:"level"`
	At      string  `json:"at"`
}
```

`Store` 接口新增：

```go
	StartRun(ctx context.Context, kind string, certID int64, deploymentID *int64, trigger string) (*Run, error)
	FinishRun(ctx context.Context, runID int64, status, errMsg string) error
	AppendEvent(ctx context.Context, runID int64, e Event) error
	ListRuns(ctx context.Context, certID int64) ([]Run, error)
	ListRunEvents(ctx context.Context, runID int64) ([]Event, error)
```

- [ ] **Step 4: 实现 runs.go**

`internal/db/runs.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"fmt"
)

// StartRun opens a run, numbering it one past the certificate's highest
// existing attempt of the same kind so the UI can group retries.
func (s *SQLite) StartRun(ctx context.Context, kind string, certID int64,
	deploymentID *int64, trigger string) (*Run, error) {

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var attempt int64
	// Scoping the attempt counter to (certificate, kind, deployment) keeps
	// issuance attempts and each target's deployment attempts on their own
	// numbering.
	err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(attempt), 0) + 1 FROM runs
		 WHERE certificate_id = ? AND kind = ?
		   AND ((deployment_id IS NULL AND ? IS NULL) OR deployment_id = ?)`,
		certID, kind, deploymentID, deploymentID).Scan(&attempt)
	if err != nil {
		return nil, fmt.Errorf("compute run attempt: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO runs (kind, certificate_id, deployment_id, attempt, trigger, status)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		kind, certID, deploymentID, attempt, trigger, RunStatusRunning)
	if err != nil {
		return nil, fmt.Errorf("start run: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	run := &Run{
		ID: id, Kind: kind, CertificateID: certID, DeploymentID: deploymentID,
		Attempt: attempt, Trigger: trigger, Status: RunStatusRunning,
	}
	return run, nil
}

func (s *SQLite) FinishRun(ctx context.Context, runID int64, status, errMsg string) error {
	var errValue any
	if errMsg != "" {
		errValue = errMsg
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE runs SET status = ?, error = ?, finished_at = datetime('now') WHERE id = ?`,
		status, errValue, runID)
	if err != nil {
		return fmt.Errorf("finish run %d: %w", runID, err)
	}
	return requireAffected(res)
}

// AppendEvent adds a timeline entry, assigning the next sequence number
// within the run.
func (s *SQLite) AppendEvent(ctx context.Context, runID int64, e Event) error {
	level := e.Level
	if level == "" {
		level = LevelInfo
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO events (run_id, seq, type, message, detail, level)
		 VALUES (?, (SELECT COALESCE(MAX(seq), 0) + 1 FROM events WHERE run_id = ?), ?, ?, ?, ?)`,
		runID, runID, e.Type, e.Message, e.Detail, level)
	if err != nil {
		return fmt.Errorf("append event to run %d: %w", runID, err)
	}
	return nil
}

const runColumns = `id, kind, certificate_id, deployment_id, attempt, trigger,
	status, error, started_at, finished_at`

func (s *SQLite) ListRuns(ctx context.Context, certID int64) ([]Run, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT `+runColumns+` FROM runs WHERE certificate_id = ? ORDER BY id DESC`, certID)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()

	out := []Run{}
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.Kind, &r.CertificateID, &r.DeploymentID,
			&r.Attempt, &r.Trigger, &r.Status, &r.Error, &r.StartedAt, &r.FinishedAt); err != nil {
			return nil, fmt.Errorf("scan run: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) ListRunEvents(ctx context.Context, runID int64) ([]Event, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, run_id, seq, type, message, detail, level, at
		 FROM events WHERE run_id = ? ORDER BY seq ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("list run events: %w", err)
	}
	defer rows.Close()

	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.RunID, &e.Seq, &e.Type, &e.Message,
			&e.Detail, &e.Level, &e.At); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/db/ -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 6: 提交**

```bash
git add internal/db/
git commit -m "feat(db): runs and events tables backing the unified timeline"
```

---

### Task 4: Pebble 测试 CA 脚手架

进程内的 ACME 测试 CA，后续三个任务都靠它。**这些依赖只出现在 `_test.go` 里**，不进生产依赖图。

**Files:**
- Create: `internal/issuance/testca_test.go`
- Modify: `go.mod`（加 pebble 与 challtestsrv 为测试依赖）

**Interfaces:**
- Produces（仅测试可见）：
  - `func newTestCA(t *testing.T) *testCA`
  - `type testCA struct { DirectoryURL string; HTTPClient *http.Client; DNS *fakeDNSProvider }`
  - `type fakeDNSProvider struct{...}` — 实现 `dns.Provider`，按 `(name, value)` 精确增删

- [ ] **Step 1: 加测试依赖**

```bash
go get github.com/letsencrypt/pebble/v2@v2.10.0
go get github.com/letsencrypt/challtestsrv@v1.4.2
```

- [ ] **Step 2: 写脚手架**

`internal/issuance/testca_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/letsencrypt/challtestsrv"
	"github.com/letsencrypt/pebble/v2/ca"
	pebbledb "github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
)

// testCA is an in-process ACME CA: Pebble for the protocol, challtestsrv as
// the DNS server Pebble's validator resolves TXT records against. No
// network, no Docker — a full DNS-01 issuance runs in well under a second.
type testCA struct {
	DirectoryURL string
	HTTPClient   *http.Client
	DNS          *fakeDNSProvider
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	// Pebble sleeps a random interval before validating unless told not to.
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	challSrv, err := challtestsrv.New(challtestsrv.Config{
		DNSAddrs: []string{dnsAddr},
		Log:      log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("challtestsrv.New: %v", err)
	}
	go challSrv.Run()
	t.Cleanup(challSrv.Shutdown)

	logger := log.New(io.Discard, "pebble ", 0)
	memDB := pebbledb.NewMemoryStore()
	pebbleCA := ca.New(logger, memDB, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default", ValidityPeriod: 0},
	})
	// The empty httpPort/tlsPort are unused for DNS-01; dnsAddr is what
	// makes the validator resolve our TXT records instead of the internet's.
	pebbleVA := va.New(logger, 0, 0, true, dnsAddr, memDB)
	wfeImpl := wfe.New(logger, memDB, pebbleVA, pebbleCA, nil, true, false, 0, 0)

	srv := httptest.NewUnstartedServer(wfeImpl.Handler())
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return &testCA{
		DirectoryURL: srv.URL + wfe.DirectoryPath,
		HTTPClient:   srv.Client(),
		DNS:          &fakeDNSProvider{srv: challSrv},
	}
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// fakeDNSProvider implements dns.Provider on top of challtestsrv.
//
// It keeps its own name→values map instead of delegating removal straight
// to challtestsrv, whose DeleteDNSTXTRecord drops every value for a name.
// Mirroring the real (name, value) contract is the point: a provider that
// deletes too much is exactly the bug milestone 2a fixed, and a fake that
// also deletes too much would hide it.
type fakeDNSProvider struct {
	srv *challtestsrv.ChallSrv

	mu     sync.Mutex
	values map[string][]string
	// AddErr/RemoveErr let a test inject provider failures.
	AddErr    error
	RemoveErr error
}

func (f *fakeDNSProvider) AddTXT(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.AddErr != nil {
		return f.AddErr
	}
	if f.values == nil {
		f.values = map[string][]string{}
	}
	f.values[name] = append(f.values[name], value)
	f.srv.AddDNSTXTRecord(name, value)
	return nil
}

func (f *fakeDNSProvider) RemoveTXT(_ context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.RemoveErr != nil {
		return f.RemoveErr
	}
	kept := make([]string, 0, len(f.values[name]))
	for _, v := range f.values[name] {
		if v != value {
			kept = append(kept, v)
		}
	}
	f.values[name] = kept

	// challtestsrv only offers "delete every value for this name", so
	// re-add the survivors.
	f.srv.DeleteDNSTXTRecord(name)
	for _, v := range kept {
		f.srv.AddDNSTXTRecord(name, v)
	}
	return nil
}

// Values reports the records currently present, for assertions.
func (f *fakeDNSProvider) Values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.values[name]))
	copy(out, f.values[name])
	return out
}

func TestTestCAStartsAndServesDirectory(t *testing.T) {
	caSrv := newTestCA(t)
	resp, err := caSrv.HTTPClient.Get(caSrv.DirectoryURL)
	if err != nil {
		t.Fatalf("fetching the directory: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("directory status = %d, want 200", resp.StatusCode)
	}
}

func TestFakeDNSProviderRemovesOnlyTheGivenValue(t *testing.T) {
	// 这个假 provider 自己就得先正确，否则后面的断言都没意义。
	caSrv := newTestCA(t)
	ctx := context.Background()
	name := "_acme-challenge.example.com"

	if err := caSrv.DNS.AddTXT(ctx, name, "first"); err != nil {
		t.Fatal(err)
	}
	if err := caSrv.DNS.AddTXT(ctx, name, "second"); err != nil {
		t.Fatal(err)
	}
	if got := caSrv.DNS.Values(name); len(got) != 2 {
		t.Fatalf("values = %v, want both present", got)
	}
	if err := caSrv.DNS.RemoveTXT(ctx, name, "first"); err != nil {
		t.Fatal(err)
	}
	got := caSrv.DNS.Values(name)
	if len(got) != 1 || got[0] != "second" {
		t.Errorf("values = %v, want only [second]", got)
	}
	if live := caSrv.DNS.srv.GetDNSTXTRecords(name); len(live) != 1 || live[0] != "second" {
		t.Errorf("challtestsrv records = %v, want only [second]", live)
	}
}
```

- [ ] **Step 3: 跑测试确认脚手架可用**

Run: `go test ./internal/issuance/ -v`
Expected: 两个用例 PASS。若 challtestsrv 起不来，检查 UDP 端口是否被占。

- [ ] **Step 4: 确认测试依赖没进生产依赖图**

```bash
go list -deps ./cmd/certcenter | grep -iE 'pebble|challtestsrv' && echo "!!! 测试依赖泄漏进二进制" || echo "生产依赖图干净 ✓"
CGO_ENABLED=0 go build ./... && echo "build OK"
```

Expected: 打印"生产依赖图干净 ✓"

- [ ] **Step 5: 提交**

```bash
git add go.mod go.sum internal/issuance/
git commit -m "test(issuance): in-process Pebble ACME test CA with a DNS-01 fake"
```

---

### Task 5: ACME 账户注册与导入

**Files:**
- Create: `internal/issuance/account.go`
- Test: `internal/issuance/account_test.go`

**Interfaces:**
- Consumes: `testCA`（Task 4）、`db.ACMEAccount`（Task 1）
- Produces:
  - `func GenerateAccountKey() (string, error)` — 新 P-256 密钥的 PKCS#8 PEM
  - `func ParseAccountKey(pemStr string) (crypto.Signer, error)`
  - `type Registrar struct { HTTPClient *http.Client }`
  - `func (r *Registrar) Register(ctx, directoryURL, email, keyPEM string) (accountURL string, err error)`
  - `func (r *Registrar) Verify(ctx, directoryURL, accountURL, keyPEM string) error` — 导入时验活

- [ ] **Step 1: 写失败的测试**

`internal/issuance/account_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
)

func TestGenerateAndParseAccountKey(t *testing.T) {
	pemStr, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("key PEM starts with %q, want a PKCS#8 header", pemStr[:30])
	}

	signer, err := ParseAccountKey(pemStr)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("ParseAccountKey returned %T, want *ecdsa.PrivateKey", signer)
	}
	if name := ec.Curve.Params().Name; name != "P-256" {
		t.Errorf("curve = %q, want P-256", name)
	}
}

func TestParseAccountKeyRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"",
		"not pem at all",
		"-----BEGIN PRIVATE KEY-----\nnotbase64!!\n-----END PRIVATE KEY-----\n",
	} {
		if _, err := ParseAccountKey(in); err == nil {
			t.Errorf("ParseAccountKey(%q) = nil error, want failure", in)
		}
	}
}

func TestRegisterAgainstTestCA(t *testing.T) {
	caSrv := newTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}

	r := &Registrar{HTTPClient: caSrv.HTTPClient}
	accountURL, err := r.Register(context.Background(), caSrv.DirectoryURL,
		"admin@example.com", keyPEM)
	if err != nil {
		t.Fatalf("Register() = %v", err)
	}
	if accountURL == "" {
		t.Error("Register returned an empty account URL")
	}
	if !strings.HasPrefix(accountURL, "https://") {
		t.Errorf("accountURL = %q, want an absolute URL", accountURL)
	}
}

func TestVerifyAcceptsARegisteredAccount(t *testing.T) {
	// 导入流程：调用方给出私钥与账户 URL，我们回 CA 确认这对组合有效，
	// 而不是把用户填的东西直接信了存库。
	caSrv := newTestCA(t)
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	r := &Registrar{HTTPClient: caSrv.HTTPClient}
	accountURL, err := r.Register(context.Background(), caSrv.DirectoryURL, "a@b.c", keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Verify(context.Background(), caSrv.DirectoryURL, accountURL, keyPEM); err != nil {
		t.Errorf("Verify() on a freshly registered account = %v, want nil", err)
	}
}

func TestVerifyRejectsAMismatchedKey(t *testing.T) {
	caSrv := newTestCA(t)
	r := &Registrar{HTTPClient: caSrv.HTTPClient}

	realKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	accountURL, err := r.Register(context.Background(), caSrv.DirectoryURL, "a@b.c", realKey)
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(context.Background(), caSrv.DirectoryURL, accountURL, otherKey); err == nil {
		t.Error("Verify() with the wrong key = nil error, want rejection")
	}
}

func TestRegisterRejectsBadDirectory(t *testing.T) {
	r := &Registrar{}
	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(context.Background(),
		"https://127.0.0.1:1/directory", "a@b.c", keyPEM); err == nil {
		t.Error("Register against an unreachable directory = nil error, want failure")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/issuance/ -run 'AccountKey|Register|Verify' -v`
Expected: 编译失败，`undefined: GenerateAccountKey`

- [ ] **Step 3: 实现 account.go**

`internal/issuance/account.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Package issuance obtains certificates over ACME DNS-01, driving the
// protocol state machine step by step so every phase lands in the run's
// event timeline.
package issuance

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/mholt/acmez/v3/acme"
)

// GenerateAccountKey returns a fresh ECDSA P-256 key as PKCS#8 PEM.
//
// PKCS#8 PEM is deliberately a portable format: the Rust implementation
// stored instant-acme's bespoke JSON credential blob, which nothing else
// can read. A PEM key can be moved between certbot, lego and us.
func GenerateAccountKey() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal account key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ParseAccountKey decodes a PKCS#8 PEM private key.
func ParseAccountKey(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("account key is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("account key of type %T cannot sign", key)
	}
	return signer, nil
}

// Registrar creates and validates accounts at a CA.
type Registrar struct {
	// HTTPClient overrides the transport, which the tests use to trust the
	// in-process Pebble CA's self-signed certificate.
	HTTPClient *http.Client
}

func (r *Registrar) client(directoryURL string) *acme.Client {
	return &acme.Client{
		Directory:  directoryURL,
		HTTPClient: r.HTTPClient,
		// The protocol library's own logging is discarded: our timeline
		// comes from explicit AppendEvent calls, not from scraped logs.
		// (This is the property lego could not provide — its logger is a
		// process-global, so concurrent issuances interleave.)
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// Register creates a new account at the CA and returns its URL (the ACME
// "kid"). Terms of service are accepted on the operator's behalf, matching
// the Rust implementation's behaviour.
func (r *Registrar) Register(ctx context.Context, directoryURL, email, keyPEM string) (string, error) {
	signer, err := ParseAccountKey(keyPEM)
	if err != nil {
		return "", err
	}
	account := acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           signer,
	}
	if email != "" {
		account.Contact = []string{"mailto:" + email}
	}
	registered, err := r.client(directoryURL).NewAccount(ctx, account)
	if err != nil {
		return "", fmt.Errorf("register ACME account: %w", err)
	}
	return registered.Location, nil
}

// Verify checks that an imported (key, account URL) pair is live at the CA,
// so a bad import fails at save time rather than at the first issuance.
func (r *Registrar) Verify(ctx context.Context, directoryURL, accountURL, keyPEM string) error {
	signer, err := ParseAccountKey(keyPEM)
	if err != nil {
		return err
	}
	_, err = r.client(directoryURL).GetAccount(ctx, acme.Account{
		Location:   accountURL,
		PrivateKey: signer,
	})
	if err != nil {
		return fmt.Errorf("verify ACME account: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/issuance/ -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
git add internal/issuance/
git commit -m "feat(issuance): ACME account registration and import verification"
```

---

### Task 6: 证书材料辅助（CSR、链拆分、日期解析）

把签发流程里纯计算的部分单独拿出来，可以脱离网络详尽测试。

**Files:**
- Create: `internal/issuance/material.go`
- Test: `internal/issuance/material_test.go`

**Interfaces:**
- Produces:
  - `func GenerateCertKey() (crypto.Signer, string, error)` — 返回 signer 与 PKCS#8 PEM
  - `func BuildCSR(signer crypto.Signer, domains []string) ([]byte, error)` — 已签名 DER
  - `func SplitChain(chainPEM []byte) (leafPEM, restPEM string, leaf *x509.Certificate, err error)`

- [ ] **Step 1: 写失败的测试**

`internal/issuance/material_test.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"crypto/x509"
	"strings"
	"testing"
)

func TestBuildCSR(t *testing.T) {
	signer, _, err := GenerateCertKey()
	if err != nil {
		t.Fatal(err)
	}
	domains := []string{"example.com", "*.example.com"}
	der, err := BuildCSR(signer, domains)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("the CSR we produced does not parse: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	// 空 Subject：CN 已被 CA/B Forum 弃用，域名只走 SAN。
	if got := csr.Subject.String(); got != "" {
		t.Errorf("Subject = %q, want empty", got)
	}
	if len(csr.DNSNames) != 2 {
		t.Fatalf("DNSNames = %v, want two entries", csr.DNSNames)
	}
	for _, want := range domains {
		found := false
		for _, got := range csr.DNSNames {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("DNSNames = %v, missing %q", csr.DNSNames, want)
		}
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Errorf("SignatureAlgorithm = %v, want ECDSAWithSHA256", csr.SignatureAlgorithm)
	}
}

func TestBuildCSRNormalizesUnicodeDomains(t *testing.T) {
	// 国际化域名必须以 punycode 进证书。自己拼 CSR 模板很容易漏掉这步，
	// 所以底层用 acmez.NewCSR。
	signer, _, err := GenerateCertKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := BuildCSR(signer, []string{"例え.テスト"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) != 1 {
		t.Fatalf("DNSNames = %v", csr.DNSNames)
	}
	if !strings.HasPrefix(csr.DNSNames[0], "xn--") {
		t.Errorf("DNSNames[0] = %q, want a punycode (xn--) form", csr.DNSNames[0])
	}
}

func TestBuildCSRRejectsNoDomains(t *testing.T) {
	signer, _, err := GenerateCertKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCSR(signer, nil); err == nil {
		t.Error("BuildCSR with no domains = nil error, want failure")
	}
}

func TestGenerateCertKeyPEMRoundTrips(t *testing.T) {
	signer, pemStr, err := GenerateCertKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("PEM header = %q, want PKCS#8", pemStr[:30])
	}
	back, err := ParseAccountKey(pemStr) // same PKCS#8 parser
	if err != nil {
		t.Fatal(err)
	}
	if !back.Public().(interface{ Equal(x any) bool }).Equal(signer.Public()) {
		t.Error("the parsed key's public part differs from the generated one")
	}
}

func TestSplitChain(t *testing.T) {
	// 规范 §14：Rust 版把整条链同时写进 cert_pem 和 chain_pem，导致详情页
	// 把叶子显示两遍、配置中心推重复的链。这里必须按 PEM 块切开。
	chain := testChainPEM(t)

	leafPEM, restPEM, leaf, err := SplitChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(leafPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("leafPEM holds %d certificates, want exactly 1",
			strings.Count(leafPEM, "BEGIN CERTIFICATE"))
	}
	if strings.Count(restPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("restPEM holds %d certificates, want the single intermediate",
			strings.Count(restPEM, "BEGIN CERTIFICATE"))
	}
	if leafPEM == restPEM {
		t.Error("leafPEM equals restPEM; nothing was actually split")
	}
	if leaf == nil {
		t.Fatal("SplitChain returned a nil leaf")
	}
	if len(leaf.DNSNames) == 0 {
		t.Error("the parsed leaf has no SANs")
	}
	if leaf.NotAfter.Before(leaf.NotBefore) {
		t.Error("leaf NotAfter precedes NotBefore")
	}
}

func TestSplitChainSingleCertificate(t *testing.T) {
	// 有些 CA（含配置为 chainLength=0 的 Pebble）只回叶子。
	// 此时 restPEM 为空且不应报错。
	full := testChainPEM(t)
	firstEnd := strings.Index(string(full), "-----END CERTIFICATE-----")
	onlyLeaf := string(full)[:firstEnd+len("-----END CERTIFICATE-----")+1]

	leafPEM, restPEM, leaf, err := SplitChain([]byte(onlyLeaf))
	if err != nil {
		t.Fatalf("SplitChain on a lone leaf = %v", err)
	}
	if restPEM != "" {
		t.Errorf("restPEM = %q, want empty", restPEM)
	}
	if leaf == nil || leafPEM == "" {
		t.Error("the leaf must still be returned")
	}
}

func TestSplitChainRejectsGarbage(t *testing.T) {
	for _, name := range []string{"空输入", "非 PEM", "PEM 但不是证书"} {
		t.Run(name, func(t *testing.T) {
			var in []byte
			switch name {
			case "空输入":
				in = nil
			case "非 PEM":
				in = []byte("hello")
			case "PEM 但不是证书":
				in = []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
			}
			if _, _, _, err := SplitChain(in); err == nil {
				t.Error("SplitChain = nil error, want failure")
			}
		})
	}
}
```

测试还需要一条证书链作夹具。这里**本地自造**，让 `SplitChain` 成为不依赖网络与 CA 的纯单元测试；"真实 CA 产出的链能被正确拆开"由 Task 7 的 `TestIssueEndToEnd` 断言（它检查 `cert_pem` 恰好一张证书且不等于 `chain_pem`），两处各司其职，不需要互相依赖。

把这两个辅助加到 `material_test.go` 末尾：

```go
// testChainPEM builds a two-certificate chain locally, so the split logic
// is unit-testable without a CA.
func testChainPEM(t *testing.T) []byte {
	t.Helper()
	leaf, leafKey := selfSigned(t, "example.com", true)
	inter, _ := selfSigned(t, "intermediate.example", false)
	_ = leafKey
	var b strings.Builder
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
	b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter}))
	return []byte(b.String())
}

func selfSigned(t *testing.T, dnsName string, isLeaf bool) ([]byte, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if isLeaf {
		tmpl.DNSNames = []string{dnsName}
	} else {
		tmpl.Subject.CommonName = dnsName
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}
```

import 需要 `crypto`、`crypto/ecdsa`、`crypto/elliptic`、`crypto/rand`、`encoding/pem`、`math/big`、`time`。

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/issuance/ -run 'CSR|CertKey|SplitChain' -v`
Expected: 编译失败，`undefined: GenerateCertKey`

- [ ] **Step 3: 实现 material.go**

`internal/issuance/material.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/mholt/acmez/v3"
)

// GenerateCertKey returns a fresh ECDSA P-256 key for a certificate,
// together with its PKCS#8 PEM encoding for storage.
func GenerateCertKey() (crypto.Signer, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate certificate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal certificate key: %w", err)
	}
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// BuildCSR produces a signed CSR (DER) covering domains, with an empty
// subject — the CN field is deprecated for domain validation, so the names
// live only in the SAN extension.
//
// acmez.NewCSR does the work because it normalizes internationalized names
// to punycode, which a hand-rolled template silently gets wrong.
func BuildCSR(signer crypto.Signer, domains []string) ([]byte, error) {
	if len(domains) == 0 {
		return nil, errors.New("no domains to request")
	}
	csr, err := acmez.NewCSR(signer, domains)
	if err != nil {
		return nil, fmt.Errorf("build CSR: %w", err)
	}
	return csr.Raw, nil
}

// SplitChain separates a CA-returned PEM chain into the leaf and the
// intermediates, and parses the leaf.
//
// Keeping them apart matters: the Rust implementation stored the whole
// chain in both cert_pem and chain_pem, so the detail view listed the leaf
// twice and the config-center deploy pushed the chain duplicated.
func SplitChain(chainPEM []byte) (string, string, *x509.Certificate, error) {
	var leafPEM string
	var leaf *x509.Certificate
	var rest strings.Builder

	remaining := chainPEM
	for i := 0; ; i++ {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return "", "", nil, fmt.Errorf("chain contains a %q block, want CERTIFICATE", block.Type)
		}
		encoded := string(pem.EncodeToMemory(block))
		if i == 0 {
			parsed, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return "", "", nil, fmt.Errorf("parse leaf certificate: %w", err)
			}
			leaf, leafPEM = parsed, encoded
			continue
		}
		rest.WriteString(encoded)
	}
	if leaf == nil {
		return "", "", nil, errors.New("chain contains no certificate")
	}
	return leafPEM, rest.String(), leaf, nil
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/issuance/ -v && go vet ./...`
Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
git add internal/issuance/
git commit -m "feat(issuance): CSR building and leaf/chain splitting"
```

---

### Task 7: 签发状态机与事件记录

本里程碑的核心：自驱 ACME 流程，每一步落一条事件。

**Files:**
- Create: `internal/issuance/issue.go`
- Create: `internal/issuance/recorder.go`
- Test: `internal/issuance/issue_test.go`

**Interfaces:**
- Consumes: 全部前置任务 + `internal/dns`
- Produces:
  - `type recorder struct{...}`、`func (r *recorder) event(type, msg, detail, level string)`
  - `type Issuer struct { Store db.Store; Registrar *Registrar; DoHServer string; DoHRetries int; DoHInterval time.Duration; HTTPClient *http.Client; NewProvider func(kind, config string) (dns.Provider, error) }`
  - `func (is *Issuer) Issue(ctx context.Context, certID int64, trigger string) error`
  - 常量 `IssueTimeout = 10 * time.Minute`
  - 测试辅助 `newTestIssuer`、`seedIssuable`（在 `issue_test.go` 里）

- [ ] **Step 1: 写失败的测试**

`internal/issuance/issue_test.go`（核心断言：证书真的签出来、时间线真的落库）：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/dns"
)

// newTestIssuer wires an Issuer against the in-process CA and a store.
func newTestIssuer(t *testing.T, caSrv *testCA) *Issuer {
	t.Helper()
	store, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	return &Issuer{
		Store:       store,
		Registrar:   &Registrar{HTTPClient: caSrv.HTTPClient},
		HTTPClient:  caSrv.HTTPClient,
		DoHRetries:  1,
		DoHInterval: time.Millisecond,
		// The fake provider stands in for whatever the certificate's DNS
		// provider row says; propagation is checked by the CA itself, so
		// the DoH verifier is bypassed in tests via SkipDoH.
		NewProvider: func(string, string) (dns.Provider, error) { return caSrv.DNS, nil },
		SkipDoH:     true,
	}
}

// seedIssuable creates an account (registered at the test CA), a DNS
// provider row, and a pending certificate; it returns the certificate id.
func seedIssuable(t *testing.T, is *Issuer, caSrv *testCA, domain string, sans []string) int64 {
	t.Helper()
	ctx := context.Background()

	keyPEM, err := GenerateAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	accountURL, err := is.Registrar.Register(ctx, caSrv.DirectoryURL, "a@b.c", keyPEM)
	if err != nil {
		t.Fatalf("registering the test account: %v", err)
	}
	acctID, err := is.Store.CreateACMEAccount(ctx, db.ACMEAccount{
		Name: "pebble", DirectoryURL: caSrv.DirectoryURL, Email: "a@b.c",
		AccountURL: &accountURL, PrivateKeyPEM: keyPEM, ValidityDays: 90,
	})
	if err != nil {
		t.Fatal(err)
	}

	sqlStore := is.Store.(*db.SQLite)
	res, err := sqlStore.DB.Exec(
		`INSERT INTO dns_providers (name, kind, config) VALUES ('fake','cloudflare','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	dnsID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	certID, err := is.Store.CreateCertificate(ctx, db.Certificate{
		Domain: domain, SANs: sans, ACMEAccountID: acctID, DNSProviderID: dnsID,
		ValidityDays: 90, AutoRenew: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certID
}

func TestIssueEndToEnd(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", []string{"*.example.com"})

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "issued" {
		t.Fatalf("status = %q, want issued (last error: %v)", cert.Status, cert.LastError)
	}

	// 叶子与链分开存。
	if cert.CertPEM == nil || cert.ChainPEM == nil {
		t.Fatal("cert_pem or chain_pem is nil")
	}
	if strings.Count(*cert.CertPEM, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("cert_pem holds %d certificates, want exactly the leaf",
			strings.Count(*cert.CertPEM, "BEGIN CERTIFICATE"))
	}
	if *cert.CertPEM == *cert.ChainPEM {
		t.Error("cert_pem equals chain_pem; the leaf was not split from the chain")
	}
	if cert.KeyPEM == "" {
		t.Error("no private key stored")
	}

	// 日期来自真实证书：Pebble 固定签 90 天，而这张证书的 validity_days
	// 也是 90，所以这里额外断言天数落在真实区间而非恰好等于配置值。
	if cert.NotBefore == nil || cert.NotAfter == nil {
		t.Fatal("not_before/not_after not populated")
	}
	nb, err := time.Parse(time.RFC3339, *cert.NotBefore)
	if err != nil {
		t.Fatalf("not_before is not RFC3339: %v", err)
	}
	na, err := time.Parse(time.RFC3339, *cert.NotAfter)
	if err != nil {
		t.Fatalf("not_after is not RFC3339: %v", err)
	}
	if days := na.Sub(nb).Hours() / 24; days < 80 || days > 100 {
		t.Errorf("validity = %.1f days, want the CA's real ~90", days)
	}
	if cert.Serial == nil || *cert.Serial == "" {
		t.Error("serial not recorded")
	}

	// TXT 记录清理干净。
	if got := caSrv.DNS.Values("_acme-challenge.example.com"); len(got) != 0 {
		t.Errorf("challenge records left behind: %v", got)
	}
}

func TestIssueWritesTheEventTimeline(t *testing.T) {
	// 规范 §14 头号缺陷：Rust 版的 log 闭包是同步闭包，内部调 async fn
	// 后立即丢弃 future，40 处调用全是空操作，certificate_events 永远为空。
	// 这个测试就是钉死"事件真的落库了"。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatalf("Issue() = %v", err)
	}

	runs, err := is.Store.ListRuns(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	run := runs[0]
	if run.Kind != db.RunKindIssue {
		t.Errorf("run kind = %q, want %q", run.Kind, db.RunKindIssue)
	}
	if run.Status != db.RunStatusSuccess {
		t.Errorf("run status = %q, want %q", run.Status, db.RunStatusSuccess)
	}
	if run.Trigger != "manual" {
		t.Errorf("run trigger = %q, want manual", run.Trigger)
	}
	if run.FinishedAt == nil {
		t.Error("run not finished")
	}

	events, err := is.Store.ListRunEvents(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 10 {
		t.Fatalf("only %d events; the timeline must cover every phase", len(events))
	}

	seen := map[string]bool{}
	for _, e := range events {
		seen[e.Type] = true
	}
	// 每个阶段都要有事件——这是选 acmez 而非 lego 换来的粒度。
	for _, want := range []string{
		"start", "load_account", "load_dns_provider", "acme_connect",
		"create_order", "get_authorizations", "dns_add", "challenge_ready",
		"poll_order", "generate_csr", "finalize_order", "download_cert",
		"save_cert", "dns_cleanup", "complete",
	} {
		if !seen[want] {
			t.Errorf("timeline is missing a %q event; got %v", want, keysOf(seen))
		}
	}

	if events[0].Type != "start" {
		t.Errorf("events[0].Type = %q, want start", events[0].Type)
	}
	last := events[len(events)-1]
	if last.Type != "complete" || last.Level != db.LevelSuccess {
		t.Errorf("last event = %s/%s, want complete/success", last.Type, last.Level)
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Errorf("events[%d].Seq = %d, want %d", i, e.Seq, i+1)
		}
	}
}

func TestIssueRecordsFailureAndCleansUp(t *testing.T) {
	// 失败路径必须：证书置 error、run 置 error、错误事件落库，
	// 且已写入的 TXT 记录被清理——Rust 版在失败时会把记录留在 DNS 上。
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	// 让挑战无法通过：TXT 写进假 provider 但不同步到 DNS 服务器。
	caSrv.DNS.SuppressDNSSync = true

	err := is.Issue(ctx, certID, "auto")
	if err == nil {
		t.Fatal("Issue() = nil error, want failure when the challenge cannot validate")
	}

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Status != "error" {
		t.Errorf("status = %q, want error", cert.Status)
	}
	if cert.LastError == nil || *cert.LastError == "" {
		t.Error("last_error not recorded")
	}

	runs, _ := is.Store.ListRuns(ctx, certID)
	if len(runs) != 1 || runs[0].Status != db.RunStatusError {
		t.Fatalf("runs = %+v, want one errored run", runs)
	}
	events, _ := is.Store.ListRunEvents(ctx, runs[0].ID)
	var sawError bool
	for _, e := range events {
		if e.Level == db.LevelError {
			sawError = true
		}
	}
	if !sawError {
		t.Error("no error-level event recorded on the failure path")
	}

	// 清理必须走 defer，失败路径也要执行。Rust 版只在成功路径清理，
	// 失败后 challenge 记录就永久留在 DNS 上。
	if got := caSrv.DNS.Values("_acme-challenge.example.com"); len(got) != 0 {
		t.Errorf("challenge records left behind after failure: %v", got)
	}
}

func TestIssueIncrementsAttempt(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	ctx := context.Background()
	certID := seedIssuable(t, is, caSrv, "example.com", nil)

	if err := is.Issue(ctx, certID, "manual"); err != nil {
		t.Fatal(err)
	}
	if err := is.Issue(ctx, certID, "auto"); err != nil {
		t.Fatal(err)
	}

	runs, _ := is.Store.ListRuns(ctx, certID)
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2", len(runs))
	}
	if runs[0].Attempt != 2 || runs[1].Attempt != 1 {
		t.Errorf("attempts = [%d %d], want [2 1]", runs[0].Attempt, runs[1].Attempt)
	}
}

func TestIssueMissingCertificate(t *testing.T) {
	caSrv := newTestCA(t)
	is := newTestIssuer(t, caSrv)
	if err := is.Issue(context.Background(), 999, "manual"); !errors.Is(err, db.ErrNotFound) {
		t.Errorf("Issue on a missing certificate = %v, want ErrNotFound", err)
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

测试用到 `fakeDNSProvider.SuppressDNSSync`，需在 Task 4 的 `testca_test.go` 里补一个字段与分支：

```go
	// SuppressDNSSync keeps AddTXT from publishing to challtestsrv, so a
	// test can make a challenge fail validation while still exercising the
	// provider and cleanup paths.
	SuppressDNSSync bool
```

`AddTXT` 里改为：

```go
	f.values[name] = append(f.values[name], value)
	if !f.SuppressDNSSync {
		f.srv.AddDNSTXTRecord(name, value)
	}
	return nil
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/issuance/ -run Issue -v`
Expected: 编译失败，`undefined: Issuer`

- [ ] **Step 3: 实现 recorder.go**

`internal/issuance/recorder.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"log/slog"

	"github.com/mrhaoxx/certcenter/internal/db"
)

// recorder writes one run's timeline. Every issuance phase calls it, which
// is the whole reason this project drives the ACME state machine itself:
// the high-level API would collapse the timeline into a single call, and
// lego's process-global logger cannot attribute lines to a certificate at
// all when issuances run concurrently.
type recorder struct {
	store db.Store
	runID int64
}

// event appends a timeline entry. A failure to record must not abort an
// otherwise healthy issuance, so it is logged and swallowed.
func (r *recorder) event(ctx context.Context, eventType, message, detail, level string) {
	e := db.Event{Type: eventType, Message: message, Level: level}
	if detail != "" {
		e.Detail = &detail
	}
	if err := r.store.AppendEvent(ctx, r.runID, e); err != nil {
		slog.Warn("could not record issuance event",
			"run", r.runID, "type", eventType, "err", err)
	}
}

func (r *recorder) info(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelInfo)
}

func (r *recorder) success(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelSuccess)
}

func (r *recorder) failure(ctx context.Context, eventType, message, detail string) {
	r.event(ctx, eventType, message, detail, db.LevelError)
}
```

- [ ] **Step 4: 实现 issue.go**

`internal/issuance/issue.go`：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

package issuance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/mholt/acmez/v3/acme"

	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/dns"
)

// IssueTimeout bounds one issuance. The Rust implementation had no overall
// deadline, so a single stuck certificate stalled the whole renewal batch.
const IssueTimeout = 10 * time.Minute

// Order polling bounds.
const (
	authzPollInterval = 2 * time.Second
	authzPollTimeout  = 150 * time.Second
)

// Issuer obtains certificates over DNS-01.
type Issuer struct {
	Store     db.Store
	Registrar *Registrar

	// DoH propagation checking; SkipDoH turns it off (tests, or an operator
	// whose resolver cannot see the record).
	DoHServer   string
	DoHRetries  int
	DoHInterval time.Duration
	SkipDoH     bool

	// HTTPClient overrides the ACME transport (tests point it at Pebble).
	HTTPClient *http.Client

	// NewProvider builds a DNS provider from a stored row; overridable so
	// tests can inject a fake.
	NewProvider func(kind, configJSON string) (dns.Provider, error)
}

func (is *Issuer) newProvider(kind, configJSON string) (dns.Provider, error) {
	if is.NewProvider != nil {
		return is.NewProvider(kind, configJSON)
	}
	return dns.New(kind, configJSON)
}

// Issue drives one full DNS-01 issuance for a certificate, recording every
// phase in the run's timeline.
func (is *Issuer) Issue(ctx context.Context, certID int64, trigger string) error {
	ctx, cancel := context.WithTimeout(ctx, IssueTimeout)
	defer cancel()

	cert, err := is.Store.GetCertificate(ctx, certID)
	if err != nil {
		return err
	}

	run, err := is.Store.StartRun(ctx, db.RunKindIssue, certID, nil, trigger)
	if err != nil {
		return fmt.Errorf("start issuance run: %w", err)
	}
	rec := &recorder{store: is.Store, runID: run.ID}

	if err := is.Store.UpdateCertificateStatus(ctx, certID, "pending", ""); err != nil {
		return err
	}

	err = is.issue(ctx, rec, cert)
	if err != nil {
		rec.failure(ctx, "failed", fmt.Sprintf("Issuance failed: %v", err), "")
		_ = is.Store.FinishRun(ctx, run.ID, db.RunStatusError, err.Error())
		_ = is.Store.UpdateCertificateStatus(ctx, certID, "error", err.Error())
		return err
	}
	_ = is.Store.FinishRun(ctx, run.ID, db.RunStatusSuccess, "")
	return nil
}

// issue is the state machine. Each step emits events; the caller turns a
// returned error into the failure bookkeeping.
func (is *Issuer) issue(ctx context.Context, rec *recorder, cert *db.Certificate) error {
	domains := append([]string{cert.Domain}, cert.SANs...)

	rec.info(ctx, "start", fmt.Sprintf("Starting certificate issuance for %s", cert.Domain),
		fmt.Sprintf("Domains: %s\nCertificate ID: %d\nACME account ID: %d\nDNS provider ID: %d",
			strings.Join(domains, ", "), cert.ID, cert.ACMEAccountID, cert.DNSProviderID))

	// ── account ────────────────────────────────────────────────────────
	rec.info(ctx, "load_account", "Loading ACME account", "")
	acct, err := is.Store.GetACMEAccount(ctx, cert.ACMEAccountID)
	if err != nil {
		rec.failure(ctx, "load_account", "Could not load the ACME account", err.Error())
		return err
	}
	signer, err := ParseAccountKey(acct.PrivateKeyPEM)
	if err != nil {
		rec.failure(ctx, "load_account", "The stored account key is unusable", err.Error())
		return err
	}
	account := acme.Account{PrivateKey: signer}
	if acct.AccountURL != nil {
		account.Location = *acct.AccountURL
	}
	rec.success(ctx, "load_account", fmt.Sprintf("ACME account %q loaded", acct.Name), "")

	// ── DNS provider ───────────────────────────────────────────────────
	rec.info(ctx, "load_dns_provider", "Loading the DNS provider", "")
	kind, configJSON, err := is.dnsProviderRow(ctx, cert.DNSProviderID)
	if err != nil {
		rec.failure(ctx, "load_dns_provider", "Could not load the DNS provider", err.Error())
		return err
	}
	provider, err := is.newProvider(kind, configJSON)
	if err != nil {
		rec.failure(ctx, "load_dns_provider", "Could not build the DNS provider", err.Error())
		return err
	}
	rec.success(ctx, "load_dns_provider", fmt.Sprintf("DNS provider loaded: %s", kind),
		redactConfig(configJSON))

	// ── connect ────────────────────────────────────────────────────────
	client := &acme.Client{
		Directory:  acct.DirectoryURL,
		HTTPClient: is.HTTPClient,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	rec.info(ctx, "acme_connect", fmt.Sprintf("Connecting to the CA at %s", acct.DirectoryURL), "")
	if _, err := client.GetDirectory(ctx); err != nil {
		rec.failure(ctx, "acme_connect", "Could not reach the CA", err.Error())
		return err
	}
	rec.success(ctx, "acme_connect", "Connected to the CA", "")

	// ── order ──────────────────────────────────────────────────────────
	ids := make([]acme.Identifier, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, acme.Identifier{Type: "dns", Value: d})
	}
	rec.info(ctx, "create_order", fmt.Sprintf("Creating an order for %d domain(s)", len(ids)), "")
	order, err := client.NewOrder(ctx, account, acme.Order{Identifiers: ids})
	if err != nil {
		rec.failure(ctx, "create_order", "The CA rejected the order", err.Error())
		return err
	}
	rec.success(ctx, "create_order", "Order created", fmt.Sprintf("Order: %s", order.Location))

	// ── authorizations ─────────────────────────────────────────────────
	rec.info(ctx, "get_authorizations",
		fmt.Sprintf("Fetching %d authorization(s)", len(order.Authorizations)), "")
	type pending struct {
		authz     acme.Authorization
		challenge acme.Challenge
	}
	var todo []pending
	// Cleanup is registered before any record is written and runs on every
	// path. The Rust implementation cleaned up only on success, so a failed
	// issuance left challenge records behind in DNS.
	type planted struct{ name, value string }
	var written []planted
	defer func() {
		if len(written) == 0 {
			return
		}
		// A fresh context: the issuance context may already be cancelled
		// or past its deadline, and cleanup still has to happen.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rec.info(cleanupCtx, "dns_cleanup",
			fmt.Sprintf("Removing %d challenge record(s)", len(written)), "")
		for _, w := range written {
			if err := provider.RemoveTXT(cleanupCtx, w.name, w.value); err != nil {
				// Non-fatal: a leftover TXT record is harmless, and failing
				// here would mask the real issuance outcome.
				rec.info(cleanupCtx, "dns_cleanup",
					fmt.Sprintf("Could not remove %s", w.name), err.Error())
			}
		}
		rec.success(cleanupCtx, "dns_cleanup", "Challenge records cleaned up", "")
	}()

	for _, authzURL := range order.Authorizations {
		authz, err := client.GetAuthorization(ctx, account, authzURL)
		if err != nil {
			rec.failure(ctx, "get_authorizations", "Could not fetch an authorization", err.Error())
			return err
		}
		if authz.Status == acme.StatusValid {
			rec.success(ctx, "dns_skip",
				fmt.Sprintf("Authorization for %s is already valid", authz.Identifier.Value), "")
			continue
		}
		var challenge acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == acme.ChallengeTypeDNS01 {
				challenge = c
				break
			}
		}
		if challenge.Type == "" {
			err := fmt.Errorf("no dns-01 challenge offered for %s", authz.Identifier.Value)
			rec.failure(ctx, "get_authorizations", err.Error(), "")
			return err
		}
		todo = append(todo, pending{authz: authz, challenge: challenge})
	}
	rec.success(ctx, "get_authorizations",
		fmt.Sprintf("%d authorization(s) need a challenge", len(todo)), "")

	// ── present every challenge before validating any ──────────────────
	// A certificate covering both example.com and *.example.com yields two
	// authorizations whose record names are identical but whose digests
	// differ. Both TXT records must exist simultaneously, which is why the
	// providers add rather than replace.
	for _, p := range todo {
		name := p.challenge.DNS01TXTRecordName()
		value := p.challenge.DNS01KeyAuthorization()
		rec.info(ctx, "dns_add", fmt.Sprintf("Adding TXT record %s", name),
			fmt.Sprintf("%s TXT %q", name, value))
		if err := provider.AddTXT(ctx, name, value); err != nil {
			rec.failure(ctx, "dns_add", fmt.Sprintf("Could not add the TXT record for %s",
				p.authz.Identifier.Value), err.Error())
			return err
		}
		written = append(written, planted{name: name, value: value})
		rec.success(ctx, "dns_add",
			fmt.Sprintf("TXT record added for %s", p.authz.Identifier.Value), "")
	}

	// ── wait for propagation ───────────────────────────────────────────
	if is.SkipDoH {
		rec.success(ctx, "dns_verify", "DNS propagation check skipped", "")
	} else {
		verifier := dns.NewVerifier(is.DoHServer, is.DoHRetries, is.DoHInterval)
		for _, w := range written {
			rec.info(ctx, "dns_verify", fmt.Sprintf("Verifying propagation of %s", w.name), "")
			if err := verifier.Wait(ctx, w.name, w.value); err != nil {
				rec.failure(ctx, "dns_verify",
					fmt.Sprintf("%s did not propagate", w.name), err.Error())
				return err
			}
			rec.success(ctx, "dns_verify", fmt.Sprintf("%s is visible", w.name), "")
		}
	}

	// ── tell the CA to validate ────────────────────────────────────────
	for _, p := range todo {
		rec.info(ctx, "challenge_ready",
			fmt.Sprintf("Telling the CA the challenge for %s is ready", p.authz.Identifier.Value), "")
		if _, err := client.InitiateChallenge(ctx, account, p.challenge); err != nil {
			rec.failure(ctx, "challenge_ready",
				fmt.Sprintf("The CA rejected our readiness notice for %s",
					p.authz.Identifier.Value), err.Error())
			return err
		}
		rec.success(ctx, "challenge_ready",
			fmt.Sprintf("CA notified for %s", p.authz.Identifier.Value), "")
	}

	// ── poll ───────────────────────────────────────────────────────────
	for _, p := range todo {
		rec.info(ctx, "poll_order",
			fmt.Sprintf("Waiting for the CA to validate %s", p.authz.Identifier.Value), "")
		final, err := client.PollAuthorization(ctx, account, p.authz)
		if err != nil {
			rec.failure(ctx, "poll_order",
				fmt.Sprintf("Validation failed for %s", p.authz.Identifier.Value), err.Error())
			return err
		}
		rec.success(ctx, "poll_order",
			fmt.Sprintf("%s validated (status %s)", p.authz.Identifier.Value, final.Status), "")
	}

	// ── CSR ────────────────────────────────────────────────────────────
	rec.info(ctx, "generate_csr", "Generating the certificate key and CSR", "")
	certSigner, keyPEM, err := GenerateCertKey()
	if err != nil {
		rec.failure(ctx, "generate_csr", "Could not generate the certificate key", err.Error())
		return err
	}
	csrDER, err := BuildCSR(certSigner, domains)
	if err != nil {
		rec.failure(ctx, "generate_csr", "Could not build the CSR", err.Error())
		return err
	}
	rec.success(ctx, "generate_csr", "CSR generated",
		fmt.Sprintf("Key: ECDSA P-256\nCSR: %d bytes\nSubject: (empty; names are SANs)", len(csrDER)))

	// ── finalize ───────────────────────────────────────────────────────
	rec.info(ctx, "finalize_order", "Submitting the CSR", "")
	order, err = client.FinalizeOrder(ctx, account, order, csrDER)
	if err != nil {
		rec.failure(ctx, "finalize_order", "The CA rejected the CSR", err.Error())
		return err
	}
	rec.success(ctx, "finalize_order", "Order finalized; the CA is signing", "")

	// ── download ───────────────────────────────────────────────────────
	rec.info(ctx, "download_cert", "Downloading the signed certificate", "")
	chains, err := client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		rec.failure(ctx, "download_cert", "Could not download the certificate", err.Error())
		return err
	}
	if len(chains) == 0 {
		err := errors.New("the CA returned no certificate chain")
		rec.failure(ctx, "download_cert", err.Error(), "")
		return err
	}
	rec.success(ctx, "download_cert", "Certificate downloaded",
		fmt.Sprintf("%d chain(s) offered; using the first", len(chains)))

	// ── save ───────────────────────────────────────────────────────────
	rec.info(ctx, "save_cert", "Saving the certificate", "")
	leafPEM, restPEM, leaf, err := SplitChain(chains[0].ChainPEM)
	if err != nil {
		rec.failure(ctx, "save_cert", "The CA's chain could not be parsed", err.Error())
		return err
	}
	issued := db.IssuedCertificate{
		CertPEM:   leafPEM,
		ChainPEM:  restPEM,
		KeyPEM:    keyPEM,
		Serial:    fmt.Sprintf("%X", leaf.SerialNumber),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
	}
	// ARI tells us when the CA would like the certificate renewed, which is
	// better than guessing from validity_days.
	//
	// SelectedTime, not SuggestedWindow.Start: acmez already picks a
	// uniformly random instant inside the window, which is the whole point
	// of ARI. Renewing at the window's start would put every certificate on
	// the same schedule and hand the CA a thundering herd.
	if info, err := client.GetRenewalInfo(ctx, leaf); err == nil {
		selected := info.SelectedTime
		issued.RenewAfter = &selected
	}
	if err := is.Store.SaveIssuedCertificate(ctx, cert.ID, issued); err != nil {
		rec.failure(ctx, "save_cert", "Could not save the certificate", err.Error())
		return err
	}
	rec.success(ctx, "save_cert", "Certificate saved",
		fmt.Sprintf("Serial: %s\nNot before: %s\nNot after: %s",
			issued.Serial,
			issued.NotBefore.UTC().Format(time.RFC3339),
			issued.NotAfter.UTC().Format(time.RFC3339)))

	rec.success(ctx, "complete",
		fmt.Sprintf("Certificate issued for %s", cert.Domain), "")
	return nil
}

// dnsProviderRow reads the provider's kind and config. It lives here rather
// than on Store because milestone 4 owns the provider CRUD; this is the one
// read issuance needs.
func (is *Issuer) dnsProviderRow(ctx context.Context, id int64) (string, string, error) {
	sqlStore, ok := is.Store.(*db.SQLite)
	if !ok {
		return "", "", errors.New("store does not expose DNS provider rows")
	}
	var kind, configJSON string
	err := sqlStore.DB.QueryRowContext(ctx,
		`SELECT kind, config FROM dns_providers WHERE id = ?`, id).Scan(&kind, &configJSON)
	if err != nil {
		return "", "", fmt.Errorf("load dns provider %d: %w", id, err)
	}
	return kind, configJSON, nil
}

// redactConfig masks credential-bearing fields so the timeline can show a
// provider's configuration without leaking secrets.
func redactConfig(configJSON string) string {
	for _, key := range []string{"api_token", "access_key_secret", "secret_key"} {
		configJSON = redactJSONField(configJSON, key)
	}
	return configJSON
}

func redactJSONField(s, key string) string {
	marker := `"` + key + `":"`
	i := strings.Index(s, marker)
	if i < 0 {
		return s
	}
	start := i + len(marker)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return s
	}
	value := s[start : start+end]
	keep := value
	if len(keep) > 4 {
		keep = keep[:4]
	}
	return s[:start] + keep + "***" + s[start+end:]
}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./internal/issuance/ -v && go test ./... && go vet ./...`
Expected: 全部 PASS。`TestIssueEndToEnd` 与 `TestIssueWritesTheEventTimeline` 是本里程碑的验收核心。

- [ ] **Step 6: 提交**

```bash
git add internal/issuance/
git commit -m "feat(issuance): DNS-01 state machine with a persisted event timeline"
```

---

### Task 8: 完成标准复核与依赖体检

**Files:** 无新增；只跑验证。

- [ ] **Step 1: 全量验证**

```bash
go build ./... && go test ./... && go vet ./...
CGO_ENABLED=0 go build -o /dev/null ./cmd/certcenter
```

- [ ] **Step 2: 测试依赖没进生产二进制**

```bash
go list -deps ./cmd/certcenter | grep -iE 'pebble|challtestsrv|testing' && echo "!!! 泄漏" || echo "生产依赖图干净 ✓"
```

- [ ] **Step 3: 确认没有云厂商 SDK 混入**

```bash
go list -deps ./... | grep -iE 'aliyun|alibaba|cloudflare-go' && echo "!!! SDK" || echo "无云厂商 SDK ✓"
```

- [ ] **Step 4: 统计并提交（若有改动）**

```bash
go test ./... -v 2>&1 | grep -cE '^(--- PASS|    --- PASS)'
```

---

## 完成标准

- `go build ./... && go test ./... && go vet ./...` 全绿，`CGO_ENABLED=0` 可编译。
- 能对着进程内 Pebble 真实签出证书，含 apex + 通配符同证书的情形。
- 事件时间线**真的落库**，覆盖全部 15 类阶段事件，`seq` 连续；这是规范 §14 头号缺陷的验收。
- 叶子与证书链分开存储（`cert_pem != chain_pem`）。
- `not_before`/`not_after`/`serial` 来自真实证书解析；有 ARI 时 `renew_after` 取其窗口起点。
- 失败路径：证书置 `error`、run 置 `error`、有 error 级事件、TXT 记录仍被清理。
- Pebble 与 challtestsrv 不在 `cmd/certcenter` 的依赖图里。

## 交接给里程碑 3 / 4 的接口

- `issuance.Issuer.Issue(ctx, certID, trigger)` — 里程碑 4 的 `POST /certificates` 与 `/renew` 调它（异步起 goroutine），里程碑 5 的调度器也调它。
- `issuance.Registrar.Register` / `.Verify` — 里程碑 4 的账户 CRUD 用。
- `issuance.GenerateAccountKey` — 创建账户时生成密钥。
- `db.Store` 已具备账户、证书、runs、events 的读写；里程碑 3 的部署引擎复用 `StartRun`/`AppendEvent`/`FinishRun`，`kind` 传 `db.RunKindDeploy`、`deploymentID` 非空。
