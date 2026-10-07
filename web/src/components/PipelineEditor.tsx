import { useState } from "react";
import { Card, Field, Input, Select, Textarea, Checkbox, cx, CopyRow } from "../ui";
import { t } from "../i18n";

/* The SSH pipeline editor. Every step type and every config key below is a
   data contract — stored deploy targets are written against these exact
   names, so a rename here silently breaks a production deployment. */

export type StepConfig = Record<string, unknown>;

export interface PipelineStep {
  type: string;
  name: string;
  config: StepConfig;
}

type FieldKind = "text" | "password" | "number" | "textarea" | "select" | "bool" | "kv" | "steps";

interface FieldSpec {
  key: string;
  label: string;
  kind: FieldKind;
  options?: string[];
  placeholder?: string;
  hint?: string;
  default?: unknown;
}

/* Where a step runs. It was implicit before — some steps used the SSH
   session and some ran on the CertCenter host — and nothing in the editor
   said which, so a pipeline could look sensible and fail on the first
   remote step. */
type RunsOn = "remote" | "local";

interface StepSpec {
  runsOn: RunsOn;
  type: string;
  label: string;
  hint: string;
  /* fatal records whether a failure aborts the pipeline. Surfacing it in
     the editor stops the surprise of a "reload" step quietly swallowing a
     non-zero exit while a "test" step tears the deployment down. */
  fatal: "always" | "never" | "onFailure";
  fields: FieldSpec[];
}

export const STEP_SPECS: StepSpec[] = [
  {
    type: "ssh_connect",
    runsOn: "remote",
    label: t("SSH 连接"),
    hint: t("必须是第一步；整条流水线共用这一个会话"),
    fatal: "always",
    fields: [
      {
        key: "id",
        label: t("连接 id"),
        kind: "text",
        hint: t("多台机器时用它区分；留空则用主机名"),
      },
      { key: "host", label: t("主机"), kind: "text", default: "127.0.0.1" },
      { key: "port", label: t("端口"), kind: "number", default: 22 },
      { key: "username", label: t("用户名"), kind: "text", default: "root" },
      { key: "auth_type", label: t("认证方式"), kind: "select", options: ["private_key", "password"], default: "private_key" },
      { key: "private_key", label: t("私钥 (PEM)"), kind: "textarea" },
      { key: "passphrase", label: t("私钥密码"), kind: "password" },
      { key: "password", label: t("密码"), kind: "password" },
      { key: "timeout_secs", label: t("连接超时（秒）"), kind: "number", default: 30 },
      {
        key: "known_host_key",
        label: t("主机密钥"),
        kind: "textarea",
        hint: t("留空则不校验主机密钥"),
      },
    ],
  },
  {
    type: "upload_file",
    runsOn: "remote",
    label: t("上传文件"),
    hint: t("失败会中断流水线；会登记路径供后续步骤引用"),
    fatal: "always",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      {
        key: "source",
        label: t("内容"),
        kind: "select",
        options: ["certificate", "private_key", "chain", "fullchain"],
        default: "certificate",
      },
      { key: "dest_path", label: t("目标路径"), kind: "text", default: "/etc/ssl/cert.pem" },
      { key: "mode", label: t("权限"), kind: "text", default: "0644", hint: t("私钥建议 0600") },
      { key: "ensure_dir", label: t("自动创建目录"), kind: "bool" },
    ],
  },
  {
    type: "run_command",
    runsOn: "remote",
    label: t("执行命令"),
    hint: t("非零退出不会中断流水线"),
    fatal: "never",
    fields: [{ key: "command", label: t("命令"), kind: "text", placeholder: "nginx -s reload" }],
  },
  {
    type: "test_command",
    runsOn: "remote",
    label: t("检查命令"),
    hint: t("非零退出会中断流水线"),
    fatal: "onFailure",
    fields: [{ key: "command", label: t("命令"), kind: "text", placeholder: "nginx -t" }],
  },
  {
    type: "backup_file",
    runsOn: "remote",
    label: t("备份文件"),
    hint: t("永不中断流水线"),
    fatal: "never",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      { key: "path", label: t("路径"), kind: "text" },
      { key: "suffix", label: t("后缀"), kind: "text", default: ".bak" },
    ],
  },
  {
    type: "write_content",
    runsOn: "remote",
    label: t("写入内容"),
    hint: t("失败会中断流水线；常用于渲染配置片段"),
    fatal: "always",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      { key: "content", label: t("内容"), kind: "textarea" },
      { key: "dest_path", label: t("目标路径"), kind: "text", default: "/tmp/output" },
      { key: "mode", label: t("权限"), kind: "text", default: "0644" },
      { key: "ensure_dir", label: t("自动创建目录"), kind: "bool" },
    ],
  },
  {
    type: "condition",
    runsOn: "remote",
    label: t("条件分支"),
    hint: t("按命令结果选择分支，最多嵌套 8 层"),
    fatal: "onFailure",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      { key: "mode", label: t("判断方式"), kind: "select", options: ["exit_code", "output_contains"], default: "exit_code" },
      { key: "command", label: t("命令"), kind: "text" },
      { key: "match_string", label: t("匹配文本"), kind: "text", hint: t("仅 output_contains 使用") },
      { key: "then_steps", label: t("条件成立时"), kind: "steps" },
      { key: "else_steps", label: t("条件不成立时"), kind: "steps" },
    ],
  },
  {
    type: "sleep",
    runsOn: "local",
    label: t("等待"),
    hint: t("永不中断流水线"),
    fatal: "never",
    fields: [{ key: "seconds", label: t("秒数"), kind: "number", default: 1 }],
  },
  {
    type: "http_request",
    runsOn: "local",
    label: t("HTTP 请求"),
    hint: t("从 CertCenter 主机发起，不走 SSH；非 2xx 不中断"),
    fatal: "onFailure",
    fields: [
      { key: "url", label: "URL", kind: "text" },
      { key: "method", label: t("方法"), kind: "select", options: ["GET", "POST", "PUT", "DELETE"], default: "GET" },
      { key: "body", label: t("请求体"), kind: "textarea" },
      {
        key: "expect_status",
        label: t("期望状态码"),
        kind: "number",
        hint: t("填了则状态不符时中断；留空只记录"),
      },
      {
        key: "insecure",
        label: t("跳过证书校验"),
        kind: "bool",
        hint: t("重载端点常就在正在换证的那台机器上，此刻它出示的还是旧证书"),
      },
    ],
  },
  {
    type: "local_write",
    runsOn: "local",
    label: t("写入本地文件"),
    hint: t("写到 CertCenter 所在机器；同机部署（共享卷）用这个，不必绕 SSH"),
    fatal: "always",
    fields: [
      {
        key: "source",
        label: t("内容"),
        kind: "select",
        options: ["certificate", "private_key", "chain", "fullchain"],
        default: "certificate",
      },
      { key: "path", label: t("路径"), kind: "text" },
      { key: "mode", label: t("权限"), kind: "text", default: "0644", hint: t("私钥用 0600") },
      { key: "ensure_dir", label: t("自动创建目录"), kind: "bool" },
      { key: "content", label: t("自定义内容"), kind: "textarea", hint: t("填了则忽略上面的内容选择") },
    ],
  },
  {
    type: "webhook",
    runsOn: "local",
    label: t("Webhook"),
    hint: t("POST 证书 JSON 到指定地址"),
    fatal: "always",
    fields: [
      { key: "url", label: "URL", kind: "text" },
      { key: "headers", label: t("请求头"), kind: "kv" },
    ],
  },
  {
    type: "configcenter_put",
    runsOn: "local",
    label: t("推送到配置中心"),
    hint: t("通过 ServerAgent 管理面写入两个配置项"),
    fatal: "always",
    fields: [
      { key: "config_key_cert", label: t("证书配置键"), kind: "text" },
      { key: "config_key_key", label: t("私钥配置键"), kind: "text" },
    ],
  },
  {
    type: "aliyun_cdn",
    runsOn: "local",
    label: t("阿里云 CDN"),
    hint: t("调用 SetDomainServerCertificate 更新证书"),
    fatal: "always",
    fields: [
      { key: "access_key_id", label: "AccessKey ID", kind: "text" },
      { key: "access_key_secret", label: "AccessKey Secret", kind: "password" },
      { key: "domain", label: t("CDN 域名"), kind: "text" },
    ],
  },
  {
    type: "tencent_cdn",
    runsOn: "local",
    label: t("腾讯云 CDN"),
    hint: t("调用 UpdateDomainConfig 更新证书"),
    fatal: "always",
    fields: [
      { key: "secret_id", label: "SecretId", kind: "text" },
      { key: "secret_key", label: "SecretKey", kind: "password" },
      { key: "domain", label: t("CDN 域名"), kind: "text" },
    ],
  },
  {
    type: "k8s_secret",
    runsOn: "local",
    label: t("Kubernetes Secret"),
    hint: t("写成 kubernetes.io/tls 类型的 Secret。集群内留空凭据即可，用 Pod 自己的 ServiceAccount"),
    fatal: "always",
    fields: [
      { key: "namespace", label: t("命名空间"), kind: "text", default: "default" },
      { key: "name", label: t("Secret 名称"), kind: "text" },
      {
        key: "leaf_only",
        label: t("只放叶子证书"),
        kind: "bool",
        hint: t("默认含中间证书，Ingress 控制器需要它"),
      },
      { key: "server", label: t("API 地址"), kind: "text", hint: t("集群外才填，如 https://k8s:6443") },
      { key: "token", label: t("Token"), kind: "password", hint: t("集群外才填") },
      { key: "ca_cert", label: t("CA 证书"), kind: "textarea", hint: t("集群外才填，PEM") },
      { key: "insecure", label: t("跳过 API 证书校验"), kind: "bool" },
    ],
  },
  {
    type: "k8s_restart",
    runsOn: "local",
    label: t("Kubernetes 滚动重启"),
    hint: t("让读取证书的服务重新加载。挂载的 Secret 会自动更新，但启动时读取证书的进程不会"),
    fatal: "always",
    fields: [
      { key: "namespace", label: t("命名空间"), kind: "text", default: "default" },
      {
        key: "kind",
        label: t("工作负载类型"),
        kind: "select",
        options: ["deployment", "statefulset", "daemonset"],
        default: "deployment",
      },
      { key: "name", label: t("名称"), kind: "text" },
      { key: "server", label: t("API 地址"), kind: "text", hint: t("集群外才填") },
      { key: "token", label: t("Token"), kind: "password", hint: t("集群外才填") },
      { key: "ca_cert", label: t("CA 证书"), kind: "textarea", hint: t("集群外才填，PEM") },
      { key: "insecure", label: t("跳过 API 证书校验"), kind: "bool" },
    ],
  },
  {
    type: "verify_ssl",
    runsOn: "local",
    label: t("验证 TLS"),
    hint: t("从 CertCenter 主机发起；握手失败仅记录不中断"),
    fatal: "onFailure",
    fields: [
      { key: "domain", label: t("域名"), kind: "text", default: "{{domain}}" },
      { key: "port", label: t("端口"), kind: "number", default: 443 },
      { key: "timeout_secs", label: t("超时（秒）"), kind: "number", default: 10 },
    ],
  },
  {
    type: "docker_exec",
    runsOn: "remote",
    label: "docker exec",
    hint: t("永不中断流水线"),
    fatal: "never",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      { key: "container", label: t("容器"), kind: "text" },
      { key: "command", label: t("命令"), kind: "text" },
    ],
  },
  {
    type: "docker_restart",
    runsOn: "remote",
    label: t("重启容器"),
    hint: t("永不中断流水线"),
    fatal: "never",
    fields: [
      {
        key: "on",
        label: t("在哪台机器"),
        kind: "text",
        hint: t("留空用最近一次 SSH 连接；多台时填连接 id"),
      },
      { key: "container", label: t("容器"), kind: "text" },
      { key: "method", label: t("方式"), kind: "select", options: ["restart", "compose_restart"], default: "restart" },
      { key: "compose_file", label: "compose 文件", kind: "text", default: "docker-compose.yml" },
    ],
  },
];

const PLACEHOLDERS = [
  "{{domain}}",
  "{{certificate}}",
  "{{private_key}}",
  "{{chain}}",
  "{{fullchain}}",
  "{{cert_path}}",
  "{{key_path}}",
  "{{chain_path}}",
];

function specFor(type: string): StepSpec | undefined {
  return STEP_SPECS.find((s) => s.type === type);
}

function defaultsFor(type: string): StepConfig {
  const spec = specFor(type);
  if (!spec) return {};
  const out: StepConfig = {};
  for (const f of spec.fields) {
    if (f.default !== undefined) out[f.key] = f.default;
  }
  return out;
}

function fatalBadge(spec: StepSpec) {
  const map = {
    always: { label: t("失败即中断"), cls: "bg-fail-soft text-fail" },
    onFailure: { label: t("条件性中断"), cls: "bg-warm-soft text-warm" },
    never: { label: t("永不中断"), cls: "bg-idle-soft text-muted" },
  } as const;
  const m = map[spec.fatal];
  return <span className={cx("rounded px-1.5 py-0.5 text-[10px] font-medium", m.cls)}>{m.label}</span>;
}

function StepFields({
  spec,
  config,
  onChange,
  depth,
}: {
  spec: StepSpec;
  config: StepConfig;
  onChange: (next: StepConfig) => void;
  depth: number;
}) {
  const set = (key: string, value: unknown) => onChange({ ...config, [key]: value });

  return (
    <div className="grid gap-3">
      {spec.fields.map((f) => {
        // Auth fields are mutually exclusive; showing both invites filling
        // in the wrong one.
        if (spec.type === "ssh_connect") {
          const auth = (config.auth_type as string) ?? "private_key";
          if ((f.key === "private_key" || f.key === "passphrase") && auth !== "private_key") return null;
          if (f.key === "password" && auth !== "password") return null;
        }
        if (spec.type === "condition" && f.key === "match_string" && config.mode !== "output_contains") {
          return null;
        }
        if (spec.type === "docker_restart" && f.key === "compose_file" && config.method !== "compose_restart") {
          return null;
        }

        const value = config[f.key];
        switch (f.kind) {
          case "bool":
            return (
              <div key={f.key}>
                <Checkbox checked={Boolean(value)} onChange={() => set(f.key, !value)} label={f.label} />
                {f.hint && <p className="mt-1 text-xs text-muted">{f.hint}</p>}
              </div>
            );
          case "select":
            return (
              <Field key={f.key} label={f.label} hint={f.hint}>
                <Select value={String(value ?? f.default ?? "")} onChange={(e) => set(f.key, e.target.value)}>
                  {f.options?.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </Select>
              </Field>
            );
          case "textarea":
            return (
              <Field key={f.key} label={f.label} hint={f.hint}>
                <Textarea value={String(value ?? "")} onChange={(e) => set(f.key, e.target.value)} placeholder={f.placeholder} />
              </Field>
            );
          case "number":
            return (
              <Field key={f.key} label={f.label} hint={f.hint}>
                <Input
                  type="number"
                  value={String(value ?? f.default ?? "")}
                  onChange={(e) => set(f.key, Number(e.target.value))}
                />
              </Field>
            );
          case "steps":
            return (
              <NestedSteps
                key={f.key}
                label={f.label}
                steps={Array.isArray(value) ? (value as PipelineStep[]) : []}
                onChange={(s) => set(f.key, s)}
                depth={depth}
              />
            );
          case "password":
            return (
              <Field key={f.key} label={f.label} hint={f.hint}>
                <Input type="password" value={String(value ?? "")} onChange={(e) => set(f.key, e.target.value)} />
              </Field>
            );
          case "kv":
            return (
              <Field key={f.key} label={f.label} hint={f.hint ?? t("每行一个 名称: 值")}>
                <Textarea
                  value={kvToText(value)}
                  onChange={(e) => set(f.key, textToKV(e.target.value))}
                  placeholder="Authorization: Bearer ..."
                />
              </Field>
            );
          default:
            return (
              <Field key={f.key} label={f.label} hint={f.hint}>
                <Input value={String(value ?? "")} onChange={(e) => set(f.key, e.target.value)} placeholder={f.placeholder} />
              </Field>
            );
        }
      })}
    </div>
  );
}

const MAX_DEPTH = 8;

/* A branch holds a sequence. It used to hold one step, so anything real —
   write the config, reload, verify — had to be expressed by nesting
   conditions inside each other. */
function NestedSteps({
  label,
  steps,
  onChange,
  depth,
}: {
  label: string;
  steps: PipelineStep[];
  onChange: (s: PipelineStep[]) => void;
  depth: number;
}) {
  if (depth >= MAX_DEPTH) {
    return (
      <p className="rounded-[9px] bg-warm-soft px-3 py-2 text-xs text-warm">
        {t("已达最大嵌套深度")} ({MAX_DEPTH})
      </p>
    );
  }

  const update = (i: number, next: PipelineStep) =>
    onChange(steps.map((s, idx) => (idx === i ? next : s)));
  const remove = (i: number) => onChange(steps.filter((_, idx) => idx !== i));
  const move = (i: number, delta: number) => {
    const target = i + delta;
    if (target < 0 || target >= steps.length) return;
    const copy = [...steps];
    [copy[i], copy[target]] = [copy[target], copy[i]];
    onChange(copy);
  };

  return (
    <div className="rounded-[9px] border border-line-strong bg-sunk p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-ink">
          {label}
          {steps.length > 0 && (
            <span className="mono ml-2 text-xs text-faint">{steps.length}</span>
          )}
        </span>
        <Select
          className="max-w-48"
          value=""
          onChange={(e) => {
            const type = e.target.value;
            if (!type) return;
            onChange([...steps, { type, name: specFor(type)?.label ?? type, config: defaultsFor(type) }]);
          }}
        >
          <option value="">{t("添加步骤…")}</option>
          {STEP_SPECS.map((sp) => (
            <option key={sp.type} value={sp.type}>
              {sp.label}
            </option>
          ))}
        </Select>
      </div>

      {steps.length === 0 && (
        <p className="text-xs text-muted">{t("没有步骤——条件成立时什么都不做")}</p>
      )}

      <div className="grid gap-2">
        {steps.map((sub, i) => {
          const spec = specFor(sub.type);
          return (
            <div key={i} className="rounded-[9px] border border-line bg-paper p-2">
              <div className="mb-2 flex items-center gap-2">
                <span className="mono text-[11px] text-faint">{i + 1}</span>
                <Input
                  value={sub.name}
                  onChange={(e) => update(i, { ...sub, name: e.target.value })}
                  className="flex-1"
                />
                <RunsOnBadge spec={spec} config={sub.config} />
                <span
                  role="button"
                  aria-label={t("上移")}
                  onClick={() => move(i, -1)}
                  className="px-1 text-xs text-faint hover:text-accent"
                >
                  ↑
                </span>
                <span
                  role="button"
                  aria-label={t("下移")}
                  onClick={() => move(i, 1)}
                  className="px-1 text-xs text-faint hover:text-accent"
                >
                  ↓
                </span>
                <span
                  role="button"
                  aria-label={t("删除")}
                  onClick={() => remove(i)}
                  className="px-1 text-xs text-faint hover:text-fail"
                >
                  ✕
                </span>
              </div>
              {spec && (
                <StepFields
                  spec={spec}
                  config={sub.config}
                  onChange={(config) => update(i, { ...sub, config })}
                  depth={depth + 1}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* Header maps are edited as text because a row-per-entry widget is more
   chrome than the one or two headers these ever carry. */
function kvToText(value: unknown): string {
  if (!value || typeof value !== "object") return "";
  return Object.entries(value as Record<string, string>)
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

function textToKV(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

/* Says where a step runs, and on which machine when a pipeline reaches
   several. Without it the local and remote steps look alike and a
   pipeline can read correctly while failing on its first remote step. */
function RunsOnBadge({ spec, config }: { spec?: StepSpec; config: Record<string, unknown> }) {
  if (!spec) return null;
  if (spec.runsOn === "local") {
    return (
      <span className="mono shrink-0 rounded bg-sunk px-1 text-[10px] text-faint" title={t("在 CertCenter 本机执行")}>
        {t("本机")}
      </span>
    );
  }
  const on = typeof config.on === "string" && config.on ? config.on : "";
  const id = typeof config.id === "string" && config.id ? config.id : "";
  const label = id || on || t("上一个连接");
  return (
    <span className="mono shrink-0 rounded bg-accent-soft px-1 text-[10px] text-accent" title={t("通过 SSH 在远端执行")}>
      {label}
    </span>
  );
}

export function PipelineEditor({
  steps,
  onChange,
}: {
  steps: PipelineStep[];
  onChange: (steps: PipelineStep[]) => void;
}) {
  const [selected, setSelected] = useState(0);

  // A pipeline starts wherever the operator wants. ssh_connect used to be
  // forced in at the top, which meant a deployment that only writes a file
  // locally still carried SSH credentials it never used.
  const normalised = steps;

  const update = (index: number, next: PipelineStep) => {
    const copy = [...normalised];
    copy[index] = next;
    onChange(copy);
  };

  const add = (type: string) => {
    onChange([...normalised, { type, name: specFor(type)?.label ?? type, config: defaultsFor(type) }]);
    setSelected(normalised.length);
  };

  const remove = (index: number) => {
    onChange(normalised.filter((_, i) => i !== index));
    setSelected((s) => Math.max(0, Math.min(s, normalised.length - 2)));
  };

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= normalised.length) return;
    const copy = [...normalised];
    [copy[index], copy[target]] = [copy[target], copy[index]];
    onChange(copy);
    setSelected(target);
  };

  const current = normalised[selected];
  const currentSpec = current ? specFor(current.type) : undefined;

  return (
    <div className="grid gap-4 lg:grid-cols-[16rem_1fr]">
      <Card className="overflow-hidden">
        <ol className="divide-y divide-line">
          {normalised.map((step, i) => {
            const spec = specFor(step.type);
            return (
              <li key={i}>
                <button
                  onClick={() => setSelected(i)}
                  className={cx(
                    "flex w-full items-center gap-2 px-3 py-2 text-left text-sm",
                    i === selected ? "bg-accent-soft text-accent" : "text-ink hover:bg-sunk",
                  )}
                >
                  <span className="mono w-5 shrink-0 text-[11px] text-faint">{i + 1}</span>
                  <span className="min-w-0 flex-1 truncate">{step.name || spec?.label || step.type}</span>
                  <RunsOnBadge spec={spec} config={step.config} />
                  {/* Every step moves and deletes. The first was pinned
                      because it had to be ssh_connect; it no longer does. */}
                  <span className="flex shrink-0 gap-0.5">
                      <span
                        role="button"
                        aria-label={t("上移")}
                        onClick={(e) => {
                          e.stopPropagation();
                          move(i, -1);
                        }}
                        className="px-1 text-faint hover:text-accent"
                      >
                        ↑
                      </span>
                      <span
                        role="button"
                        aria-label={t("下移")}
                        onClick={(e) => {
                          e.stopPropagation();
                          move(i, 1);
                        }}
                        className="px-1 text-faint hover:text-accent"
                      >
                        ↓
                      </span>
                      <span
                        role="button"
                        aria-label={t("删除")}
                        onClick={(e) => {
                          e.stopPropagation();
                          remove(i);
                        }}
                        className="px-1 text-faint hover:text-fail"
                      >
                        ✕
                      </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
        <div className="border-t border-line p-2">
          <Select
            value=""
            onChange={(e) => {
              if (e.target.value) add(e.target.value);
            }}
          >
            <option value="">{t("添加步骤…")}</option>
            {STEP_SPECS.map((s) => (
              <option key={s.type} value={s.type}>
                {s.label}
              </option>
            ))}
          </Select>
        </div>
      </Card>

      <div className="grid gap-3">
        {current && currentSpec && (
          <Card className="p-5">
            <header className="mb-4 flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold text-ink">{currentSpec.label}</h3>
              {fatalBadge(currentSpec)}
              <span
                className={cx(
                  "mono rounded px-1.5 py-0.5 text-[10px]",
                  currentSpec.runsOn === "local"
                    ? "bg-sunk text-faint"
                    : "bg-accent-soft text-accent",
                )}
              >
                {currentSpec.runsOn === "local"
                  ? t("在 CertCenter 本机执行")
                  : t("通过 SSH 在远端执行")}
              </span>
              <p className="w-full text-xs text-muted">{currentSpec.hint}</p>
            </header>
            <div className="mb-3">
              <Field label={t("步骤名称")}>
                <Input value={current.name} onChange={(e) => update(selected, { ...current, name: e.target.value })} />
              </Field>
            </div>
            <StepFields
              spec={currentSpec}
              config={current.config}
              onChange={(config) => update(selected, { ...current, config })}
              depth={0}
            />
          </Card>
        )}

        <Card className="p-4">
          <p className="eyebrow mb-2">{t("可用变量")}</p>
          <div className="flex flex-wrap gap-1.5">
            {PLACEHOLDERS.map((p) => (
              <CopyRow key={p} value={p} />
            ))}
          </div>
          <p className="mt-2 text-xs text-muted">
            {t("{{cert_path}} 等路径由上传步骤自动登记；{{fullchain}} 是叶子证书加中间证书。")}
          </p>
        </Card>
      </div>
    </div>
  );
}

/* parsePipeline reads a stored target config into steps, tolerating the
   legacy flat form the backend still accepts. */
export function parsePipeline(configJSON: string): PipelineStep[] {
  if (!configJSON.trim()) return [];
  try {
    const parsed = JSON.parse(configJSON) as { steps?: PipelineStep[] };
    if (Array.isArray(parsed.steps)) return parsed.steps;
    return [];
  } catch {
    return [];
  }
}

export function serialisePipeline(steps: PipelineStep[]): string {
  return JSON.stringify({ steps }, null, 2);
}
