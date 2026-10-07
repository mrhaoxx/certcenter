# CertCenter

自托管的 SSL/TLS 证书管理平台：通过 ACME DNS-01 自动签发与续期证书，再用一条可编排的流水线把证书送到需要它的地方——SSH 主机、Kubernetes、CDN、Webhook、本地文件、ServerAgent 配置中心。

Go 后端 + React 前端，编译为**单个二进制**（前端经 `go:embed` 嵌入），运行时只需一个数据卷。

## 用 Docker 部署

不需要 clone 仓库，也不需要本机装 Go 或 Node：

```bash
mkdir -p certcenter/data && cd certcenter
curl -O https://raw.githubusercontent.com/mrhaoxx/certcenter/main/docker-compose.yml
curl -o data/config.toml https://raw.githubusercontent.com/mrhaoxx/certcenter/main/config.example.toml
```

编辑 `data/config.toml`，两处必须改：

```bash
# 会话密钥：至少 32 字节。示例里的占位值会让服务拒绝启动
openssl rand -hex 32

# 管理员密码散列（示例里的散列对应密码 admin）
htpasswd -nbBC 12 "" "你的密码" | cut -d: -f2
```

```bash
docker compose up -d
```

访问 `http://<主机>:3001`。

镜像是 `ghcr.io/mrhaoxx/certcenter`，由 GitHub Actions 在每次推送 `main` 和打 `v*` 标签时构建，多架构（amd64 / arm64），约 63MB，以 nonroot 运行。生产建议钉版本而不是 `latest`：

```yaml
image: ghcr.io/mrhaoxx/certcenter:v0.1.2
```
想跑自己的代码就把 compose 里的 `image:` 换成 `build: .`——镜像自带前端构建，两条路都不需要本机有 Node 或 Go。

### 几点说明

**数据全在 `./data`**：SQLite 数据库（含 ACME 账户私钥、DNS 凭据、证书私钥）和 `config.toml`。备份就是备份这个目录，或用设置页的加密导出。

**只能单副本。** SQLite 是单写者，连接池固定为 1。要多实例得先换掉存储层。

**不需要暴露到公网。** 签发走 DNS-01，CA 不需要访问这个服务；只有你自己要访问控制台。

**`[bus]` 是可选的**，只在接入 ServerAgent 时才配。不用它就整段删掉。

### 反向代理后面

```bash
docker compose run --rm certcenter -config /data/config.toml \
  -external-url https://certs.example.com
```

或在 compose 的 `command` 里加 `-external-url`。它启用 `Secure` cookie 与 Origin 校验；不填则不做跨源检查（单域名直连时够用）。

### 升级

```bash
docker compose pull && docker compose up -d
```

数据库迁移在启动时自动执行且可重复运行，不需要手工步骤。

## 用 Helm 部署

Chart 发布在 `oci://ghcr.io/mrhaoxx/charts/certcenter`，版本号与镜像标签一致：

```bash
helm install certcenter oci://ghcr.io/mrhaoxx/charts/certcenter --version 0.1.2 \
  --set config.sessionKey="$(openssl rand -hex 32)" \
  --set config.passwordHash='<htpasswd 生成的散列>'
```

只有 `config.sessionKey` 是必填的；不填 `passwordHash` 则首次登录密码为 `admin`。`config.toml` 由 chart 渲染进 Secret，也可以用 `existingSecret` 指向自己维护的 Secret（键名 `config.toml`）。开启 `ingress` 后 `-external-url` 会自动按 ingress 的 host 推导。

**存储**：`persistence.type` 可选 `pvc`（默认）、`hostPath` 或 `emptyDir`。hostPath 把数据库放在节点目录里，方便从宿主机备份，代价是 Pod 固定在那个节点，记得配 `nodeSelector`。镜像以 uid 65532 运行，chart 会用一个 init 容器把新建的宿主目录 chown 过去。

**本地部署**：`localDeploy.hostPaths` 把节点上的目录挂进容器，流水线里的 `local_write` 步骤就能把证书直接写到宿主机，比如给跑在节点上的 nginx 用：

```yaml
persistence:
  type: hostPath
  hostPath: { path: /var/lib/certcenter }
localDeploy:
  fixPermissions: true
  hostPaths:
    - name: nginx
      hostPath: /etc/nginx/certs
      mountPath: /host/nginx
nodeSelector:
  kubernetes.io/hostname: edge-1
```

然后在部署目标里把 `local_write` 的路径指向 `/host/nginx/...`。完整参数见 `charts/certcenter/values.yaml`。

Deployment 固定单副本、`Recreate` 策略，原因同上：SQLite 单写者。

## 从源码构建

```bash
./hack/build-webui.sh          # 构建前端到 web/dist（需要 Node ≥ 20）
CGO_ENABLED=0 go build -o certcenter ./cmd/certcenter
./certcenter -config config.toml
```

SQLite 驱动是纯 Go 的（`modernc.org/sqlite`），所以 `CGO_ENABLED=0` 成立，运行镜像可以用 distroless。

`web/dist/index.html` 提交了一个占位文件，因此没装 Node 也能直接 `go build ./...`。

## 架构

```
cmd/certcenter        入口：配置加载、装配、优雅退出
internal/config       TOML 配置；支持配置中心推送的稀疏合并
internal/db           SQLite 存储层（唯一实现，测试用内存库跑同一份 schema）
internal/dns          DNS-01 的 TXT 记录操作：Cloudflare、阿里云
internal/cloudsign    云厂商请求签名：阿里云 ACS3、腾讯云 TC3
internal/issuance     ACME 状态机（acmez 低层客户端）与事件时间线
internal/deploy       部署流水线：19 种步骤与编排
internal/scheduler    续期调度
internal/bus          ServerAgent 总线协议与 RPC
internal/server       HTTP API、会话认证、SSE、嵌入式 SPA
internal/backup       age 加密的全量导出与原子恢复
internal/secret       凭据脱敏；HTTP 与总线两条通道共用，避免只遮一边
web                   Vite + React 控制台
```

## 功能

- **签发与续期**：ACME DNS-01，支持通配符与 apex 同证书；支持 ARI（CA 推荐的续期窗口）
- **DNS 提供商**：Cloudflare、阿里云 DNS；自动跟随 `_acme-challenge` 的 CNAME 委派，拿不到主域权限时也能签
- **加密备份**：设置页一键导出，age 格式，用标准 `age` 命令即可解开
- **部署流水线**：一个目标就是一串步骤，可跨多台机器。19 种步骤——SSH（连接/上传/执行/条件分支等）、Kubernetes Secret 与滚动重启、本地文件、HTTP 请求、Webhook、CDN、配置中心
- **证书选项**：密钥算法（EC/RSA）、ACME profile、请求有效期、首选证书链、续期是否换私钥、从现成 CSR 签发
- **吊销与导出**：支持吊销原因；PEM 与 PKCS#12（.pfx）导出
- **事件时间线**：签发与部署的每一步都落库，可按尝试次数折叠查看
- **自动续期**：每小时扫描，失败按指数退避重试，不会因一次失败就永久停摆
- **总线集成**：作为 `service:certcenter` 接入 ServerAgent，暴露 27 个 RPC 方法，支持配置热更新
- **审计日志**：所有变更操作留痕；下载私钥单独记录

## 配置

见 `config.example.toml`。要点：

- `auth.session_key` 至少 32 字节，占位值会被拒绝启动
- `auth.password_hash` **只在首次启动时**播种管理员密码；之后以数据库为准，通过界面改密码立即生效、无需重启
- `[bus]` 可选；配置后会从配置中心拉取并合并配置，且接受运行时推送

## 开发

```bash
go test ./...                  # 全部测试，含对进程内 Pebble CA 的真实 ACME 签发
cd web && npm run dev          # 前端开发服务器，代理到 localhost:3001
```

签发链路的集成测试用 `pebble` + `challtestsrv` 在进程内起一个 ACME 测试 CA，不出网、不需要 Docker，一次完整的 DNS-01 签发不到一秒。这两个依赖只出现在测试中，不进生产二进制。

## 许可

Apache-2.0
