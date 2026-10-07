# CertCenter Go 重写 — 设计文档

日期：2026-07-26
状态：待评审

## 1. 目标

把 CertCenter 从 Rust（axum + instant-acme + rusqlite）整体重写为 Go，前端从 Next.js/shadcn 重写为 Vite/React，工程约定对齐同一作者的 plat101 项目。

功能对等：ACME 证书签发与自动续期（DNS-01）、五类部署目标、ServerAgent 总线集成、事件时间线、操作日志、单管理员认证。API 与数据模型允许重新设计，不迁移旧数据。

顺带修掉重写过程中发现的四个现存缺陷（见 §14）——它们不是"顺手优化"，其中两个导致核心功能实际不可用。

## 2. 决策摘要

| 项 | 决策 | 理由 |
|---|---|---|
| ACME 协议层 | `github.com/mholt/acmez/v3` 低层 `acme.Client` 自驱状态机 | 13 个依赖模块；把 NewOrder/InitiateChallenge/PollAuthorization/FinalizeOrder 作为独立方法暴露，事件时间线的每一步都能落库；带 ARI（`GetRenewalInfo`）；JWS/nonce/重试由库负责 |
| HTTP 层 | 标准库 `net/http` + Go 1.22 路由模式 | 对齐 plat101，无框架 |
| 数据库 | SQLite via `modernc.org/sqlite` v1.54 | 纯 Go 无 cgo，保持单二进制 + 单数据卷；证书管理是低写入单节点场景 |
| SSH | `golang.org/x/crypto/ssh` | 替换 libssh2，纯 Go |
| 总线 msgpack | `github.com/vmihailenco/msgpack/v5` | 需与 ServerAgent 现有二进制协议逐字节兼容 |
| WebSocket | `github.com/gorilla/websocket` | 对齐 plat101 |
| 前端 | Vite + React 18 + react-router-dom v6 + @tanstack/react-query v5 + Tailwind v4 | 对齐 plat101，复用 Soft Console token 体系与手写 `ui.tsx` |
| 配置 | 保留 TOML + 总线配置中心热更新 | 配置中心推的就是渲染好的 TOML，是外部契约 |
| 数据迁移 | 不做 | 用户确认重新录入 |

被明确否决的方案：lego（日志是包级全局变量，并发签发时无法按证书归属事件，时间线只能降级到十来条粗粒度记录）；lego 内置 DNS provider（依赖从 16 个模块膨胀到 250 个）；CertMagic（它自己管存储和续期，与我们的调度器职责冲突）。

## 3. 仓库结构

原地替换：删除 `backend/`（Rust）与 `frontend/`（Next.js），新布局对齐 plat101。

```
cmd/certcenter/main.go        # 入口：flag 解析、配置加载、装配 Server、启动
internal/config/config.go     # TOML schema、校验、稀疏合并（配置中心推送用）
internal/db/
  store.go                    # Store 接口 + 领域类型（JSON tag 即 API 形状）
  sqlite.go                   # 唯一实现
  schema.sql                  # 建表语句（embed）
  testdb.go                   # 测试辅助：内存 SQLite（跑真实 schema）
internal/server/
  server.go                   # Server 结构体、Routes()、writeJSON/writeErr、中间件
  auth.go                     # 登录、会话、改密码
  certificates.go             # 证书 CRUD、签发/续期/部署触发、下载
  certinfo.go                 # X.509 解析（详情页）
  accounts.go                 # ACME 账户 CRUD + 导入
  dnsproviders.go             # DNS 提供商 CRUD
  deploytargets.go            # 部署目标 CRUD
  runs.go                     # 运行记录与事件时间线查询
  logs.go                     # 操作日志
  events.go                   # SSE /api/events（缓存失效广播）
  bus_rpc.go                  # 总线 RPC 方法 → handler 复用
internal/issuance/               # 注意不叫 acme：避免与 acmez 的 acme 包名冲突
  issue.go                    # 签发编排（状态机自驱 + 事件发射）
  account.go                  # 账户注册/导入/加载（crypto.Signer 持久化）
  solver.go                   # acmez.Solver + Waiter 实现（桥接 dns 包）
internal/dns/
  provider.go                 # Provider 接口 + 工厂
  cloudflare.go
  aliyun.go                   # 含 ACS3-HMAC-SHA256 签名
  doh.go                      # DoH 传播校验
internal/deploy/
  target.go                   # Target 接口、CertificateData、Event
  deploy.go                   # 编排：遍历绑定、写运行记录与事件
  ssh.go                      # 12 种 pipeline 步骤
  webhook.go
  configcenter.go
  aliyuncdn.go
  tencentcdn.go
internal/bus/
  frame.go                    # 30 字节帧头编解码
  client.go                   # 引导握手、心跳、订阅、重连
  config.go                   # config.resolve 拉取 + 热更新
web/
  embed.go                    # //go:embed all:dist
  package.json vite.config.ts tsconfig.json
  src/{main.tsx,api.ts,ui.tsx,i18n.ts,index.css,pages/*.tsx,components/*.tsx}
docs/superpowers/{specs,plans}
Dockerfile hack/build-webui.sh
```

`internal/server` 每个文件一个领域，`Server` 结构体聚合依赖，`Routes()` 装配 mux——完全照 plat101 的模式。

源文件头部统一：

```go
// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0
```

## 4. 数据模型

现有 schema 有两处值得重新设计：`certificate_events` 与 `deployment_events` 是两张近乎相同的表，UI 要写两套时间线组件；以及管理员密码散列存在 config.toml 里，导致改密码要去做字符串替换。

新 schema 用一组 `runs` + `events` 统一两类时间线，管理员凭据移入数据库。

```sql
CREATE TABLE acme_accounts (
  id            INTEGER PRIMARY KEY,
  name          TEXT    NOT NULL,
  directory_url TEXT    NOT NULL,   -- CA 目录 URL，签发时实际使用
  email         TEXT    NOT NULL,
  account_url   TEXT,               -- CA 分配的账户 URL（kid）
  private_key   TEXT    NOT NULL,   -- PKCS#8 PEM，ECDSA P-256
  validity_days INTEGER NOT NULL DEFAULT 90,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE dns_providers (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,          -- cloudflare | aliyun
  config     TEXT NOT NULL,          -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE certificates (
  id              INTEGER PRIMARY KEY,
  domain          TEXT    NOT NULL,
  sans            TEXT    NOT NULL DEFAULT '[]',  -- JSON 数组
  acme_account_id INTEGER NOT NULL REFERENCES acme_accounts(id),
  dns_provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  cert_pem        TEXT,              -- 叶子证书，单个 PEM 块
  chain_pem       TEXT,              -- 中间证书，不含叶子
  key_pem         TEXT,              -- PKCS#8 PEM
  serial          TEXT,              -- 十六进制，来自真实证书
  not_before      TEXT,              -- 来自真实证书，RFC3339
  not_after       TEXT,              -- 来自真实证书，RFC3339
  renew_after     TEXT,              -- ARI 建议窗口起点；无则由 §12 公式回退
  validity_days   INTEGER NOT NULL DEFAULT 90,
  status          TEXT    NOT NULL DEFAULT 'pending',  -- pending|issued|error|expired
  last_error      TEXT,
  auto_renew      INTEGER NOT NULL DEFAULT 1,
  retry_count     INTEGER NOT NULL DEFAULT 0,   -- 连续失败次数，驱动退避
  retry_after     TEXT,                          -- 下次允许自动重试的时间
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE deploy_targets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,          -- ssh|webhook|configcenter|aliyun_cdn|tencent_cdn
  config     TEXT NOT NULL,          -- JSON
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE deployments (                      -- 证书 × 部署目标 的绑定
  id               INTEGER PRIMARY KEY,
  certificate_id   INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deploy_target_id INTEGER NOT NULL REFERENCES deploy_targets(id) ON DELETE CASCADE,
  status           TEXT    NOT NULL DEFAULT 'pending',  -- pending|success|failed
  last_deployed_at TEXT,
  last_error       TEXT,
  UNIQUE(certificate_id, deploy_target_id)
);

CREATE TABLE runs (                             -- 一次签发或一次部署
  id             INTEGER PRIMARY KEY,
  kind           TEXT    NOT NULL,              -- issue | deploy
  certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deployment_id  INTEGER REFERENCES deployments(id) ON DELETE CASCADE,  -- kind=deploy 时非空
  attempt        INTEGER NOT NULL,
  trigger        TEXT    NOT NULL,              -- manual|auto|api|bus
  status         TEXT    NOT NULL DEFAULT 'running',  -- running|success|error
  error          TEXT,
  started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  finished_at    TEXT
);

CREATE TABLE events (                           -- 时间线条目
  id      INTEGER PRIMARY KEY,
  run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  seq     INTEGER NOT NULL,
  type    TEXT    NOT NULL,
  message TEXT    NOT NULL,
  detail  TEXT,
  level   TEXT    NOT NULL DEFAULT 'info',      -- info|success|error
  at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX events_run ON events(run_id, seq);

CREATE TABLE operation_logs (
  id            INTEGER PRIMARY KEY,
  action        TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   INTEGER,
  detail        TEXT,
  operator      TEXT NOT NULL DEFAULT 'admin',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE settings (                         -- 管理员凭据等可变配置
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
```

启用 `PRAGMA foreign_keys = ON`（现有实现声明了外键但从未启用，所以级联删除全靠手写 SQL），以及 `journal_mode = WAL`、`busy_timeout = 5000`。

`Store` 接口定义在 `internal/db/store.go`，领域结构体的 JSON tag 直接就是 API 形状——不再有单独的 DTO 层。

与 plat101 的一处有意偏离：plat101 有 `pg.go` 与 `mem.go` 两个实现、handler 测试跑内存实现，本项目**只做 SQLite 一个实现**，测试用内存 SQLite（`:memory:` + `SetMaxOpenConns(1)`，跑同一份 `schema.sql`）。理由是我们的查询含真实逻辑——尤其 §12 续期选取的日期运算——平行的内存实现得把这些 SQL 语义重写一遍，一旦与真实实现分叉，测试就会在"通过"的同时掩盖线上错误。内存 SQLite 兼得速度与真实性。

连接池设为 `SetMaxOpenConns(1)`：SQLite 单写者，本项目写入极稀疏，用单连接换掉一整类 `SQLITE_BUSY` 竞态。

## 5. 配置与启动

TOML schema 保持兼容（配置中心推的是渲染好的 TOML，改 schema 等于改外部契约），仅去掉已移入数据库的字段：

```toml
[server]
host = "0.0.0.0"
port = 3001

[database]
path = "/data/certcenter.db"

[auth]
session_key = "..."        # 原 jwt_secret 改名；>= 32 字节
username = "admin"
password_hash = "$2a$12$..."   # 仅作首次启动的种子，之后以数据库为准

[dns_verification]
skip = false
doh_server = "https://cloudflare-dns.com/dns-query"
max_retries = 12

[bus]
url = "ws://localhost:9900/ws"
service_id = "certcenter"
token = "..."
management_url = "ws://localhost:9901/api/events/ws"
```

`auth.password_hash` 的语义变化：首次启动时若 `settings` 表无 `admin_password_hash`，用配置值播种；之后改密码只写数据库，配置里的值被忽略。这样彻底消灭"改密码靠对 config.toml 做字符串替换、且不重启不生效"的现状。

启动顺序（`cmd/certcenter/main.go`）：

1. `flag`：`--config`（默认 `config.toml`，兼容位置参数）、`--listen` 覆盖。
2. 加载 TOML；文件不存在则用默认值并告警（保持现有行为）。
3. 若配置了 `[bus]`，先做一次 `config.resolve` 拉取并稀疏合并（失败仅告警）。
4. `Validate()`：检查 host 非空、port 非 0、db path 非空、`session_key` 长度 ≥ 32 且不是占位值。
5. 校验通过则打开数据库、跑迁移、装配 `Server`、启动 HTTP 监听与续期调度器；校验失败则**不监听**，等配置中心推送（保持现有行为）。
6. 无论是否启动成功，都起总线客户端协程（带配置监听）。
7. `signal.NotifyContext` + `httpSrv.Shutdown` 优雅退出。

热更新语义与现状一致：共享 `atomic.Pointer[Config]`，handler 每次请求读取，所以 `dns_verification`、管理员用户名等即时生效；`server.host/port`、`database.path` 仅在服务尚未启动时生效。

日志用 `log/slog` JSON handler，对齐 plat101。

## 6. 认证

单管理员，改用 plat101 的会话模型替换 JWT：

- HMAC 签名的会话令牌，写 `HttpOnly` Cookie（HTTPS 下加 `Secure`），同时支持 `Authorization: Bearer <token>` 供脚本调用。
- 密钥来自 `auth.session_key`，有效期 24 小时。
- `originGuard`：对 POST/PUT/PATCH/DELETE 校验 `Origin` 头，防 CSRF（Cookie 认证必需，现有 JWT-in-header 方案不需要，但换成 Cookie 后必需）。
- `limitBody`：变更类请求体上限 256 KiB。
- 密码散列 bcrypt cost 12，从 `settings` 表读取。

免认证路径：`GET /healthz`、`POST /api/auth/login`、静态资源。注意现有实现用的是"路径以 `/auth/login` 结尾"的后缀匹配，改为精确匹配。

## 7. HTTP API

错误信封统一（plat101 约定）：

```json
{ "code": "NOT_FOUND", "message": "no such certificate", "detail": null }
```

路由表：

```
GET    /healthz

POST   /api/auth/login              {username,password} → 设置 Cookie，返回 {user}
POST   /api/auth/logout
GET    /api/me                      → {user, features}
PUT    /api/me/password             {oldPassword,newPassword}

GET    /api/dashboard               → 统计
GET    /api/events?topics=a,b       → SSE，缓存失效广播

GET    /api/certificates?search=&status=
POST   /api/certificates            → 201，异步签发
GET    /api/certificates/{id}
PATCH  /api/certificates/{id}       {autoRenew?,validityDays?,deployTargetIds?}
DELETE /api/certificates/{id}
GET    /api/certificates/{id}/x509  → 解析后的证书与证书链详情
GET    /api/certificates/{id}/bundle → {domain,certPem,keyPem,chainPem}（唯一暴露私钥的端点）
POST   /api/certificates/{id}/renew  → 202
POST   /api/certificates/{id}/deploy → 202
GET    /api/certificates/{id}/deployments
GET    /api/certificates/{id}/runs   → 该证书的签发与部署运行记录
GET    /api/runs/{id}/events         → 一次运行的完整事件时间线

GET    /api/acme-accounts
POST   /api/acme-accounts            → 向 CA 注册新账户
POST   /api/acme-accounts/import     → 导入已有账户（PEM 私钥 + 账户 URL）
PATCH  /api/acme-accounts/{id}
DELETE /api/acme-accounts/{id}

GET    /api/dns-providers
POST   /api/dns-providers
PATCH  /api/dns-providers/{id}
DELETE /api/dns-providers/{id}

GET    /api/deploy-targets
POST   /api/deploy-targets
PATCH  /api/deploy-targets/{id}
DELETE /api/deploy-targets/{id}

GET    /api/logs?limit=&offset=
```

相对现状的改动：`PUT` 改 `PATCH`（都是部分更新，语义更准）；`/info` 改 `/x509`、`/download` 改 `/bundle`（名字说清它做什么）；两条事件端点合并为 `/api/runs/{id}/events`；新增 `/api/events` SSE 与 `/api/me`。

删除语义分两类，避免与 §4 的外键级联混淆：

- **删证书**：级联删除其绑定、运行记录与事件（`ON DELETE CASCADE` 负责）。这是期望行为——证书没了，它的历史也就没有归属。
- **删部署目标 / DNS 提供商 / ACME 账户**：若仍被证书引用，返回 **409** 并在 `detail` 里列出引用者，不级联。`deployments` 上的 `ON DELETE CASCADE` 仅作为删证书路径的兜底，正常不会由这条路径触发。现有实现在这里是静默级联，删一个部署目标会连带删掉绑定并把事件表孤儿化。

SSE 主题：`certificates`、`runs`、`deployments`、`logs`。前端用 plat101 的 `useEventInvalidate` 把主题映射到 react-query key，签发过程实时刷新，不再轮询。这是现状下体验最差的一块——签发要跑一两分钟，UI 只能靠轮询。

静态资源与 SPA 回退照 plat101：路径含 `.` 走文件服务，否则回 `index.html`。

## 8. ACME 签发引擎

`internal/issuance/issue.go` 自驱状态机，每步前后写事件。骨架：

```go
type Issuer struct {
    Store   db.Store
    Config  func() *config.Config   // 读热更新配置
    Runs    *RunRecorder            // 事件发射，见下
}

func (is *Issuer) Issue(ctx context.Context, certID int64, trigger string) error
```

`RunRecorder` 负责在 `runs` 插一行、按 `seq` 递增写 `events`、结束时回填 `status`/`finished_at`，并向 SSE 广播。所有事件都带 run 归属，天然支持并发签发——这正是选 acmez 而非 lego 的原因。

流程（括号内为发射的事件类型，沿用现有 18 类命名以便前端图标/文案复用）：

1. 建 run（`start`）。
2. 载入 ACME 账户：解析 PEM 私钥为 `crypto.Signer`，组装 `acme.Account{Location: account_url, PrivateKey: signer}`（`load_credentials`）。
3. 载入 DNS 提供商配置，日志 detail 中对 `api_token`/`access_key_secret` 做前 4 字符 + `***` 脱敏（`load_dns_config`）。
4. `acme.Client{Directory: directoryURL}`，`GetDirectory`（`acme_connect`）。
5. `NewOrder`，identifiers = `[domain] + sans`。若证书已有历史且 CA 支持 ARI，填 `Order.Replaces` 以便 CA 关联替换关系（`create_order`）。
6. 逐个 `GetAuthorization`（`get_authorizations`）。
7. 每个授权：
   - 已 `valid` 则跳过（`dns_skip`）。
   - 取 `dns-01` challenge，`challenge.DNS01TXTRecordName()` 得记录名，`DNS01KeyAuthorization()` 得摘要——不再手工拼 `_acme-challenge.` 前缀。
   - `solver.Present`：调 DNS provider 写 TXT（`dns_add`）。
   - `solver.Wait`：DoH 传播校验，默认 `https://cloudflare-dns.com/dns-query`，12 次重试、间隔 5 秒，可由配置覆盖或跳过（`dns_verify`）。
   - `InitiateChallenge`（`challenge_ready`）。
8. `PollAuthorization` 等所有授权变 `valid`。acmez 内部尊重 `Retry-After`；外层每 3 次轮询发一条进度事件（`poll_order`）。
9. 生成 ECDSA P-256 密钥与 CSR：空 Subject DN，SAN 为全部域名（`generate_csr`）。
10. `FinalizeOrder`（`finalize_order`）。
11. `GetCertificateChain` → `[]acme.Certificate`，取首个链的 `ChainPEM`（`download_cert`）。
12. **按 PEM 块拆分**：block[0] 为叶子写 `cert_pem`，其余拼接写 `chain_pem`。解析叶子的真实 `NotBefore`/`NotAfter`/`Serial` 入库。若 `Certificate.RenewalInfo` 非空，把 ARI 建议窗口起点写 `renew_after`（`save_cert`）。
13. `solver.CleanUp` 清理 TXT 记录。**用 `defer` 注册，使失败路径也清理**（`dns_cleanup`）。
14. 触发部署（`deploy`）、收尾（`complete`）。

超时参数集中为常量：DoH 12 次 × 5 秒、授权轮询上限 150 秒、证书下载上限 60 秒。整个 `Issue` 外层套一个 10 分钟 `context.WithTimeout`——现有实现没有总超时，一次卡住的签发会拖住整个续期批次。

账户管理（`account.go`）：注册走 `NewAccount`（`TermsOfServiceAgreed: true`），把 `crypto.Signer` 序列化为 PKCS#8 PEM 存 `private_key`，`Location` 存 `account_url`。导入接受 PEM 私钥 + 账户 URL，并调一次 `GetAccount` 验活。不再使用 instant-acme 的自定义 JSON 凭据格式（无迁移需求，且 PEM 是通用格式，将来能和 certbot/lego 互换）。

## 9. DNS Provider

```go
type Provider interface {
    AddTXT(ctx context.Context, name, value string) error
    RemoveTXT(ctx context.Context, name, value string) error
}

func New(kind, configJSON string) (Provider, error)   // cloudflare | aliyun
```

`name` 为完整记录名（无尾点），`value` 为未加引号的原始摘要。

**Cloudflare**：配置 `{api_token, zone_id}`，`Authorization: Bearer`。`AddTXT` 用 `url.Values` 正确编码查询参数（现有实现直接拼接未编码），创建记录 TTL 120。**不再做"先删同名记录再添加"**——那正是 apex + 通配符同证书场景下互相覆盖的根因（两个授权算出同一记录名但摘要不同）。改为纯追加，配合 §8 的 defer 清理。同时检查响应体的 `success` 字段，现有实现只看 HTTP 状态码，2xx 但 `success:false` 会被当成成功。

**阿里云 AliDNS**：配置 `{access_key_id, access_key_secret, domain}`。记录名 RR 由 FQDN 剥去 `.{domain}` 后缀得到；若后缀不匹配则报错，而不是像现在这样静默地在错误的 zone 里建记录。

ACS3-HMAC-SHA256 签名必须逐字节复刻（端点 `https://alidns.aliyuncs.com`，版本 `2015-01-09`）：

1. 动作参数按 key 字节序排序。
2. `CanonicalQueryString` = `percentEncode(k)=percentEncode(v)` 以 `&` 连接。编码规则 RFC 3986：保留 `A-Za-z0-9-_.~`，其余按**字节**转大写 `%XX`（空格是 `%20` 不是 `+`）。
3. `body_hash` = `hex(sha256(""))`，参数全部走查询串，body 恒空。
4. 待签头（按小写名排序）：`host`、`x-acs-action`、`x-acs-content-sha256`、`x-acs-date`（`2006-01-02T15:04:05Z`）、`x-acs-signature-nonce`（UUIDv4 带连字符）、`x-acs-version`。
5. `CanonicalRequest` = `"POST\n/\n" + query + "\n" + headers + "\n" + signedHeaders + "\n" + bodyHash`，其中 headers 每行 `k:v\n`。
6. `StringToSign` = `"ACS3-HMAC-SHA256\n" + hex(sha256(CanonicalRequest))`。
7. `Signature` = `hex(hmacSHA256(secret, StringToSign))`，小写。
8. `Authorization: ACS3-HMAC-SHA256 Credential={ak},SignedHeaders={sh},Signature={sig}`（逗号后无空格）。

**关键实现约束**：发送的 URL 查询串必须与签名时的字符串完全一致，因此手工拼接 URL 字符串，不能用 `url.Values.Encode()`（它把空格编成 `+`，签名立即失效）。这一点写成注释留在代码里，并配一个签名黄金测试（固定输入 → 固定签名）防回归。

动作：`AddDomainRecord`、`DescribeDomainRecords`（补上分页，现有实现依赖默认 20 条/页）、`DeleteDomainRecord`。保留重复记录处理：命中 `DomainRecordDuplicate` 时列出同 RR 的 TXT 记录、删除后重试一次。

`doh.go` 的 DoH 校验给 HTTP 客户端设 10 秒超时（现有实现无超时），`Status == 3`（NXDOMAIN）视为未传播而非错误。TXT 比较处理资源记录被解析器切成多段引号串的情况——现有实现用 `trim_matches('"')` 做全等比较，长 TXT 会匹配失败。

## 10. 部署引擎

接口保持"事件与错误成对返回"的设计（事件在失败时也要落库）：

```go
type Event struct {
    Type, Message string
    Detail        string
    Level         string   // info | success | error
}

type Target interface {
    Deploy(ctx context.Context, cert *CertificateData) ([]Event, error)
}

func New(kind, configJSON string) (Target, error)
```

编排（`deploy.go`）与现状一致：串行遍历绑定，每个绑定开一个 `kind=deploy` 的 run，先发 `start` 事件，跑完更新绑定的 `status`/`last_deployed_at`/`last_error`；单个目标失败不影响其余目标。`configcenter` 类型在构造前从应用配置注入 `management_url`。

### SSH pipeline

12 种步骤全部保留，配置键与语义逐一对齐现状（完整目录见附录 A——**那些 key 是数据契约，生产环境已有的部署目标配置就是按它们写的，不能改名**）。要点：

- 两种配置形态：`{steps:[...]}` 或旧版扁平形态（含 `host` 键），后者在构造时脱糖为 pipeline。
- 首步必须是 `ssh_connect`，空 steps 报错。
- **整条 pipeline 共用一个 SSH 会话**，每条命令开新 channel，因此 `cd`、环境变量不跨步骤保留。
- 模板变量：`{{domain}}`、`{{certificate}}`、`{{private_key}}`、`{{chain}}`、`{{cert_path}}`、`{{key_path}}`、`{{chain_path}}`。后三个由 `upload_file` 步骤按其 `source` 动态登记。
- 致命与非致命的区分必须保留：`upload_file`、`test_command`、`write_content`、`ensure_dir` 失败中断；`run_command` 非零退出、HTTP 非 2xx、TLS 握手失败、`docker_exec`/`docker_restart` 非零退出仅记录。
- `condition` 支持 `then_step`/`else_step` 递归嵌套。**加深度上限 8 层**，现有实现无限制。
- 未知步骤类型记一条 info 事件后跳过，不报错。

相对现状的改进：`ssh_connect` 增加连接超时（现在用 OS 默认）与主机密钥校验选项（`known_hosts` 路径或显式指纹；默认仍不校验以保持兼容，但配置可开启）；`http_request` 与 `verify_ssl` 加超时；私钥支持带密码短语。

### Webhook

`POST` JSON `{domain, certificate, private_key, chain}`，自定义头覆盖默认头，加 30 秒超时。无内置签名机制（认证靠自定义头传 token），保持现状。

### ConfigCenter

连管理面 WebSocket（JSON 协议，无引导握手），发两条 `config.put` RPC，key 分别为 `config_key_cert`/`config_key_key`，`format: "text"`，10 秒总超时。cert 侧推的是 fullchain——注意新 schema 下 `cert_pem` 是纯叶子，所以这里要显式拼 `cert_pem + "\n" + chain_pem`（现状因为两列存的是同一份完整链，拼出来是重复的两遍）。

### 阿里云 / 腾讯云 CDN

**现状这两个是空壳**：只发一条 `not yet implemented` 错误事件就返回，凭据读进结构体后直接丢弃。"功能对等"在这里等于对等地什么都不做。

**已决定：本次实现为真**（评审确认）。阿里云 CDN 用 `SetDomainServerCertificate`，签名与 AliDNS 共用 §9 的 ACS3 实现（几乎零成本）；腾讯云 CDN 用 `UpdateDomainConfig`，需新增 TC3-HMAC-SHA256 签名（约 50 行）。

两者都要有签名黄金测试与 `httptest` 假 API 的请求形状测试，理由同 §9：签名一错就是运行时才暴露的静默失败。

## 11. 总线集成

二进制协议是与 ServerAgent 的外部契约，**逐字节保持不变**。

帧头固定 30 字节：

| 偏移 | 长度 | 字段 | 编码 |
|---|---|---|---|
| 0 | 1 | version | 1=JSON payload，2=msgpack |
| 1 | 1 | type | 1=REQUEST 2=RESPONSE 3=EVENT 4=HEARTBEAT 5=PUSH |
| 2 | 16 | uuid | 原始字节 |
| 18 | 8 | timestamp | int64 Unix 秒，大端 |
| 26 | 4 | payload_len | uint32 大端 |

本服务一律发 version=2（msgpack，named fields）。

生命周期：连接 → 引导握手（JSON 文本帧 `{bootstrap:"service", service_id, token, labels, methods}`，10 秒内等 `bootstrap == "accepted"`）→ 发 EVENT 帧订阅 `config:watch:certcenter` → 进入二进制帧循环。断开后 5 秒重连。

帧处理：REQUEST 串行分发并回 RESPONSE；HEARTBEAT 回一个新 UUID、空 payload 的心跳帧（纯被动响应，不主动发起）；PUSH 解 `{topic, data}`，topic 前缀匹配 `config:watch:certcenter` 则触发配置重载（重新 `config.resolve` → 稀疏合并 → 校验 → 原子替换；若服务此前因配置无效未启动，此时启动）。

RPC 请求 payload 形如 `{type:"PluginTask", plugin, action, params}`，`action` 即方法名；响应 payload 为 msgpack 的 `{success, exit_code, stdout, stderr}`，成功时把结果 JSON **字符串化后放进 `stdout`**（不是嵌套结构）。这个别扭的约定也是外部契约，保持。

27 个 `cert.*` 方法全部保留原名（改名会打破调用方），实现上复用 handler 层逻辑。完整方法名与参数见附录 B。

**安全说明**：总线 RPC 完全绕过 HTTP 认证，仅靠引导 token，而其中 `cert.download`（新名 bundle）会返回私钥。这是现状的信任模型——总线连接本身被视为可信。本次保持不变，但在代码注释与文档中显式标注，并给 `cert.download` 单独记一条操作日志（operator = `bus`），使私钥外发有审计痕迹。

## 12. 续期调度

用 `time.Ticker` 每小时扫描，而不是 cron 固定 02:00——现有实现是每天 02:00 UTC 跑一次，若那一刻进程刚重启就整天不检查。每小时扫描对"到期"这种以天为单位的判断完全够用，且对重启免疫。

选取条件修正现有实现最严重的行为缺陷：**续期失败一次就永久停摆**（失败置 `status='error'`，而筛选条件是 `status='issued'`，此后再也扫不到）。

```sql
SELECT ... FROM certificates
WHERE auto_renew = 1
  AND status IN ('issued', 'error')
  AND (retry_after IS NULL OR retry_after <= datetime('now'))
  AND (
        (renew_after IS NOT NULL AND renew_after <= datetime('now'))
     OR (renew_after IS NULL AND not_after IS NOT NULL
         AND julianday(not_after) - julianday('now') <= validity_days * 0.2)
      )
```

即：优先用 ARI 给出的续期窗口；没有 ARI 时回退到"剩余寿命 ≤ 总时长 20%"的现有规则。因为 `not_after` 现在来自真实证书（不再是按 `validity_days` 估算的值），这个阈值第一次真正准确。

失败处理：`retry_count++`，`retry_after = now + min(2^retry_count 小时, 24 小时)` 指数退避，并写一条操作日志（现有实现在调度路径上不写操作日志，失败完全无痕）。成功则清零 `retry_count`/`retry_after`。

并发：同一时刻最多 3 张证书并行签发（现有实现完全串行，一张卡住拖垮整批；配合 §8 的 10 分钟总超时双重保险）。

## 13. 前端

Vite + React 18 + react-router-dom v6 + @tanstack/react-query v5 + Tailwind v4，直接复用 plat101 的 Soft Console token 体系（`--color-paper/surface/sunk/ink/muted/faint/line/line-strong/accent` 与 `run/warm/idle/fail` 四态色）与手写 `ui.tsx` 组件层。不引入 shadcn/Radix。

```
web/src/
  main.tsx        # createBrowserRouter 路由表
  api.ts          # req<T>() 薄封装 + 每端点一个导出函数 + 类型
  ui.tsx          # Shell/Card/Button/Input/Field/Select/Checkbox/Pager/
                  # StatusDot/PhaseLabel/Notice/CopyRow/CopyBlock/
                  # useEventInvalidate/ThemeToggle
  i18n.ts         # zh/en，t()
  index.css       # @theme token + 暗色主题
  components/
    Timeline.tsx        # runs + events 时间线（签发与部署共用一套）
    PipelineEditor.tsx  # SSH pipeline 可视化编辑
    X509View.tsx        # 证书与证书链详情
  pages/
    Login.tsx  Dashboard.tsx
    Certificates.tsx  CertificateDetail.tsx
    AcmeAccounts.tsx  DnsProviders.tsx
    DeployTargets.tsx  Logs.tsx  Settings.tsx
```

四态色到本领域的映射：`run` = 已签发/部署成功，`warm` = 签发中/即将过期，`idle` = 待处理，`fail` = 错误/已过期。

`CertificateDetail` 用标签页承载概览、X.509 详情、事件时间线、部署状态，替代现在分散在 `/certificates/detail`、`/certificates/events`、`/deployments/events` 三个页面的结构。

统一 `Timeline` 组件是 §4 合并 `runs`/`events` 表的直接收益——签发和部署的时间线渲染逻辑只写一份，按 `attempt` 分组折叠。

`PipelineEditor` 是最大的单块重写（现有 Next.js 版 1016 行）。12 种步骤各有自己的配置表单，需要逐个对照现有实现移植；模板变量提供插入辅助。

SSE：`useEventInvalidate({certificates:[["certificates"]], runs:[["runs"]], ...})` 一条 `EventSource` 连 `/api/events`，收到主题信号即失效对应 query。签发过程实时推进，彻底去掉轮询。

Vite dev proxy 指向 `http://localhost:3001`。

## 14. 要修的现存缺陷

调研阶段在 Rust 实现里发现的问题，重写时必须修掉，不能等价移植：

1. **事件时间线是死代码，一行都没写进过数据库。** `acme/client.rs:80` 的 `log` 是同步闭包，内部调用 `async fn log_event` 后立即丢弃 future，从不 await。签发流程约 40 处调用全是空操作，`certificate_events` 无任何写入点。前端的证书事件页面因此永远是空的。→ §8 的 `RunRecorder` 真实落库。
2. **续期失败一次即永久停摆。** 见 §12。这是最严重的运维缺陷：一次网络抖动就让证书静默地再也不自动续期，直到过期。
3. **叶子证书与证书链从未分离。** `certificate_pem` 与 `chain_pem` 写入同一份完整链，导致详情页把叶子显示两遍、配置中心部署推的是重复两遍的链。→ §8 步骤 12 按 PEM 块拆分。
4. **`not_before`/`not_after` 是估算值而非真实值。** 取 `now` 与 `now + validity_days`，Let's Encrypt 实际固定签 90 天，所以 `validity_days != 90` 时库里的到期时间就是错的——而续期调度器恰好拿这两个值算阈值。→ §8 解析真实证书。

另外三个边界问题：apex + 通配符同证书时两个授权算出同一 TXT 记录名而摘要不同、后写覆盖先写（→ §9 改为追加 + defer 清理）；签发失败路径不清理 TXT 记录（→ §8 defer）；DoH 与各 HTTP 客户端无超时（→ 全部设超时）。

## 15. 测试策略

按 TDD 推进，测试与代码同目录（plat101 约定，其 `internal/server` 约半数文件是测试）。

- `internal/db`：内存 SQLite 跑真实 `schema.sql`，覆盖 CRUD、级联删除、`runs`/`events` 顺序、续期选取 SQL 的边界（刚好等于阈值、已过期、退避未到期）。注意内存库的 `journal_mode` 返回 `memory` 而非 `wal`，断言 pragma 时只对文件库检查 WAL。
- `internal/server`：`httptest` + 内存 SQLite Store，覆盖每个端点的状态码与错误信封、认证与 Origin 守卫、SSE 广播。
- `internal/issuance`：acmez 自带 `github.com/letsencrypt/pebble/v2` 依赖，用 Pebble 起本地 ACME 测试 CA 做端到端签发集成测试（DNS solver 用内存假实现）。这是现有 Rust 实现完全没有的能力。
- `internal/dns`：`httptest` 假 Cloudflare/AliDNS API 验证请求形状；ACS3 签名黄金测试（固定时间戳 + 固定 nonce → 固定签名字符串）。
- `internal/deploy`：SSH 步骤把命令执行抽象为接口，用假 runner 断言命令序列、模板展开、致命/非致命策略；`condition` 递归与深度上限。
- `internal/bus`：帧编解码往返测试 + 已知字节序列的黄金测试（保证与 ServerAgent 兼容）。
- `web`：vitest 覆盖 `api.ts` 与 PipelineEditor 的配置序列化。

## 16. 构建与部署

三阶段 Dockerfile（照 plat101）：node:22-alpine 构建 SPA → golang:1.26 以 `CGO_ENABLED=0` 编译 → `gcr.io/distroless/static` 运行，非 root 用户。因为选了纯 Go 的 SQLite 驱动，`CGO_ENABLED=0` 成立，镜像从现在的 debian-slim（需要 `libssl3`、`ca-certificates`）缩到 distroless static。

`web/dist/index.html` 提交一个占位文件，使不装 Node 也能 `go build ./...`（plat101 的做法）。

`docker-compose.yml` 保持：`./data` 卷、端口 3001、接入外部 `serveragent_default` 网络。

`.gitignore` 补上 `*.db`、`*.db-wal`、`*.db-shm`（当前 `backend/certcenter.db` 未被忽略，含私钥的数据库有进版本库的风险）。

## 17. 里程碑

本文档是单一设计文档，但**每个里程碑各出一份独立的 implementation plan**（照 plat101 的 `docs/superpowers/plans/` 惯例），逐个执行、逐个验收，不把八个里程碑塞进一份计划。

1. **骨架**：仓库布局、config、db（schema + Store + 两实现）、认证、`Server`/`Routes` 骨架、healthz。
2. **ACME**：账户管理、DNS provider（含 ACS3 签名与黄金测试）、签发引擎与事件记录、Pebble 集成测试。
3. **部署**：Target 接口、SSH 12 步骤、webhook、configcenter、两个 CDN。
4. **API 补全**：证书/账户/提供商/目标 CRUD、x509 解析、runs/events、logs、SSE。
5. **续期调度**：ticker、ARI、退避重试。
6. **总线**：帧编解码、握手、心跳、配置热更新、27 个 RPC。
7. **前端**：ui.tsx 组件层、api.ts、九个页面、Timeline、PipelineEditor、X509View。
8. **交付**：Dockerfile、compose、删除 Rust 与 Next.js 目录、README。

1 与 2 有强依赖，3–6 可在 1 之后并行，7 依赖 4。

## 18. 明确不做

- 多用户与 RBAC（单管理员足够，现状如此）。
- HTTP-01 / TLS-ALPN-01 验证（只用 DNS-01）。
- 证书吊销 API。
- 除 Cloudflare 与阿里云之外的 DNS 提供商（接口留好，按需加）。
- Postgres 支持（Store 接口天然留了口子，但不实现）。
- 数据迁移工具（用户确认重新录入）。
- 通知（邮件/webhook 告警）——值得做，但属于新功能，不在本次对等范围内。

---

## 附录 A：SSH pipeline 步骤目录

从现有 Rust 实现（`backend/src/deploy/ssh.rs`）逐行提取。**这些 JSON key 是数据契约**：生产环境已存在的部署目标配置按此编写，重命名任何一个都会静默破坏部署。里程碑 8 删除 Rust 目录前，此表是唯一权威来源。

模板变量在下表标注"展开"的字段上生效：`{{domain}}`、`{{certificate}}`（证书 PEM，注意不是 `{{cert}}`）、`{{private_key}}`（私钥 PEM，不是 `{{key}}`）、`{{chain}}`、`{{cert_path}}`、`{{key_path}}`、`{{chain_path}}`。后三个由 `upload_file` 按其 `source` 值动态登记（`certificate`→`cert_path`，`private_key`→`key_path`，`chain`→`chain_path`）；未登记则展开为空串。`write_content` 不登记路径。

### ssh_connect（必须是第一步）

| key | 默认 | 说明 |
|---|---|---|
| `host` | `127.0.0.1` | |
| `port` | `22` | |
| `username` | `root` | |
| `auth_type` | `private_key` | 仅 `private_key` / `password`，其他值报错 |
| `private_key` | `""` | PEM 文本，内存加载；空则报错 |
| `password` | `""` | |

新增（现状没有）：`timeout_secs` 连接超时、`passphrase` 私钥密码短语、`known_hosts` 主机密钥校验（留空则不校验，保持兼容）。失败中断 pipeline。

### upload_file

| key | 默认 | 说明 |
|---|---|---|
| `source` | `certificate` | `certificate`/`private_key`/`chain`，其他值致命 |
| `method` | `scp` | `scp` 或 `shell`，其他值致命 |
| `dest_path` | `/tmp/cert.pem` | **不展开模板** |
| `mode` | `0644` | 八进制字符串，解析失败回退 `0644` |
| `ensure_dir` | `false` | 先 `mkdir -p {父目录}` |

`scp` 方式原子地带上权限位；`shell` 方式用 heredoc（结束标记 `CERTCENTER_EOF`）写入，且仅当 `mode != "0644"` 时追加一条尽力而为的 `chmod`。失败中断。

### run_command

| key | 默认 | 说明 |
|---|---|---|
| `command` | `""` | 展开 |

**非零退出不致命**，仅记一条 info 事件；退出 0 记 success，输出截断 500 字节。

### test_command

| key | 默认 | 说明 |
|---|---|---|
| `command` | `""` | 展开 |

与 `run_command` 执行相同、策略相反：**非零退出中断 pipeline**。

### backup_file

| key | 默认 | 说明 |
|---|---|---|
| `path` | `""` | **不展开** |
| `suffix` | `.bak` | |

执行 `test -f {path} && cp {path} {path}{suffix} || true`，因末尾 `|| true` 实际恒为成功。永不致命。

### write_content

| key | 默认 | 说明 |
|---|---|---|
| `content` | `""` | 展开 |
| `dest_path` | `/tmp/output` | **不展开** |
| `mode` | `0644` | |
| `ensure_dir` | `false` | |

heredoc 写入，非零退出**致命**。用于从 `{{cert_path}}`/`{{certificate}}` 渲染 nginx 片段之类。

### condition

| key | 默认 | 说明 |
|---|---|---|
| `mode` | `exit_code` | `exit_code` 或 `output_contains`；其他值按 `exit_code` 处理 |
| `command` | `""` | 展开 |
| `match_string` | `""` | 仅 `output_contains` 用 |
| `then_step` | — | 完整的 `{type,name,config}` 对象 |
| `else_step` | — | 同上 |

`exit_code` 模式下退出 0 即条件成立；`output_contains` 模式下看合并输出是否含 `match_string`（忽略退出码）。选中的分支作为完整步骤递归执行，**新增深度上限 8 层**（现状无限制）。分支步骤失败会向上传播并中断 pipeline。

### sleep

| key | 默认 |
|---|---|
| `seconds` | `1` |

永不失败。Go 实现用 `time.Sleep` 配合 context 取消（现状是阻塞线程）。

### http_request

**从 CertCenter 主机发起，不走 SSH。**

| key | 默认 | 说明 |
|---|---|---|
| `url` | — | 展开 |
| `method` | `GET` | 转大写；识别 POST/PUT/DELETE，其余回退 GET |
| `body` | — | 展开；存在时强制 `Content-Type: application/json` |
| `headers` | — | 字符串映射，**值展开**，键不展开 |

传输错误致命；**非 2xx 不致命**，仅记 info。新增 30 秒超时（现状无超时）。

### verify_ssl

**同样从 CertCenter 主机发起。**

| key | 默认 | 说明 |
|---|---|---|
| `domain` | `{{domain}}` | 展开 |
| `port` | `443` | |
| `timeout_secs` | `10` | |

TCP 连接后做 TLS 握手，SNI 为该域名。**握手失败记 error 事件但不中断**，只有 DNS/TCP 层错误才致命。不校验有效期或颁发者。

### docker_exec

| key | 说明 |
|---|---|
| `container` | 展开 |
| `command` | 展开 |

执行 `docker exec {container} {command}`。永不致命。

### docker_restart

| key | 默认 | 说明 |
|---|---|---|
| `container` | — | 展开 |
| `method` | `restart` | |
| `compose_file` | `docker-compose.yml` | 仅 `method=compose_restart` 时用 |

默认执行 `docker restart {container}`；`compose_restart` 执行 `cd {compose_file 所在目录} && docker compose -f {文件名} restart {container}`。永不致命。

### 未知步骤类型

记一条 info 事件后跳过，不报错——保持现状（便于前端先行新增步骤类型而不炸后端）。

### 旧版扁平配置的脱糖

配置对象顶层含 `host` 键时按旧格式处理，等价展开为：`ssh_connect`（有 `private_key` 则 `auth_type=private_key`，否则 `password`）→ `upload_file{source:certificate, method:scp, dest_path:cert_path, mode:0644}` → `upload_file{source:private_key, ..., mode:0600}` → 有 `reload_command` 则 `run_command`。

---

## 附录 B：总线 RPC 方法清单

同样是外部契约（ServerAgent 侧按这些名字调用），Rust 目录删除后此表是唯一记录。全部绕过 HTTP 认证，仅靠引导 token——见 §11 的安全说明。

`id` 参数必须是 JSON 数字，字符串会被拒绝。更新类方法用同一个 params 对象同时取 `id` 和更新体。

| 方法 | 参数 | 返回 |
|---|---|---|
| `cert.stats` | — | 仪表盘统计 |
| `cert.list` | `{search?, status?}` | 证书数组 |
| `cert.get` | `{id}` | 证书 |
| `cert.create` | 创建证书请求体 | 证书 |
| `cert.update` | `{id, ...更新体}` | 证书 |
| `cert.delete` | `{id}` | `{"status":"ok"}` |
| `cert.renew` | `{id}` | `{"status":"ok"}` |
| `cert.deploy` | `{id}` | `{"status":"ok"}` |
| `cert.download` | `{id}` | 证书包，**含私钥**，单独记审计日志 |
| `cert.info` | `{id}` | X.509 详情 |
| `cert.events` | `{id}` = 证书 id | 事件数组 |
| `cert.deployments` | `{id}` = 证书 id | 部署绑定数组 |
| `cert.deploymentEvents` | `{id}` = **绑定** id | 事件数组 |
| `cert.acmeAccounts` | — | 账户数组 |
| `cert.createAcmeAccount` | 创建体 | 账户 |
| `cert.updateAcmeAccount` | `{id, ...}` | 账户 |
| `cert.deleteAcmeAccount` | `{id}` | `{"status":"ok"}` |
| `cert.importAcmeAccount` | 导入体 | 账户 |
| `cert.dnsProviders` | — | 提供商数组 |
| `cert.createDnsProvider` | 创建体 | 提供商 |
| `cert.updateDnsProvider` | `{id, ...}` | 提供商 |
| `cert.deleteDnsProvider` | `{id}` | `{"status":"ok"}` |
| `cert.deployTargets` | — | 目标数组 |
| `cert.createDeployTarget` | 创建体 | 目标 |
| `cert.updateDeployTarget` | `{id, ...}` | 目标 |
| `cert.deleteDeployTarget` | `{id}` | `{"status":"ok"}` |
| `cert.logs` | `{limit?, offset?}` | 操作日志数组 |

注意 `cert.events` 与 `cert.deploymentEvents` 的返回形状在新 schema 下由 `runs`+`events` 拼装（§4 合并了两张事件表），但**对外的方法名、参数含义与返回字段保持不变**，避免 ServerAgent 侧改动。
