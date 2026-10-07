import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  accountProfiles,
  createCertificate,
  KEY_TYPES,
  listAccounts,
  listCertificates,
  listProviders,
  listTargets,
  type Certificate,
} from "../api";
import {
  Button,
  Card,
  Checkbox,
  Empty,
  Field,
  Input,
  Modal,
  Notice,
  PageHeader,
  Select,
  Textarea,
  Shell,
  StatusPill,
  LifetimeBar,
  certificateTone,
  daysUntil,
  useEventInvalidate,
  formatWhen,
} from "../ui";
import { t } from "../i18n";

function NewCertificateForm({ onDone }: { onDone: () => void }) {
  const accounts = useQuery({ queryKey: ["accounts"], queryFn: listAccounts });
  const providers = useQuery({ queryKey: ["providers"], queryFn: listProviders });
  const targets = useQuery({ queryKey: ["targets"], queryFn: listTargets });

  const [domain, setDomain] = useState("");
  const [sans, setSans] = useState("");
  const [accountId, setAccountId] = useState(0);
  const [providerIds, setProviderIds] = useState<number[]>([]);
  const [profile, setProfile] = useState("");
  const [validityDays, setValidityDays] = useState("");
  const [lifetimeOpen, setLifetimeOpen] = useState(false);
  const [skipDnsCheck, setSkipDnsCheck] = useState(false);
  const [keyType, setKeyType] = useState("ec-256");
  const [csrPem, setCsrPem] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [targetIds, setTargetIds] = useState<number[]>([]);
  const [error, setError] = useState("");

  // The available profiles come from the chosen account's CA directory, so
  // the list is always what that CA actually offers today.
  const profiles = useQuery({
    queryKey: ["profiles", accountId],
    queryFn: () => accountProfiles(accountId),
    enabled: accountId > 0,
    retry: false,
  });

  const qc = useQueryClient();
  const create = useMutation({
    mutationFn: () =>
      createCertificate({
        domain: domain.trim(),
        sans: sans
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter(Boolean),
        acmeAccountId: accountId,
        dnsProviderIds: providerIds,
        profile: profile || undefined,
        validityDays: validityDays ? Number(validityDays) : undefined,
        skipDnsCheck: skipDnsCheck || undefined,
        keyType: keyType !== "ec-256" ? keyType : undefined,
        csrPem: csrPem.trim() || undefined,
        deployTargetIds: targetIds,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["certificates"] });
      onDone();
    },
    onError: (e: Error) => setError(e.message),
  });

  const ready = domain.trim() && accountId > 0 && providerIds.length > 0;
  const noPrereqs = (accounts.data?.length ?? 0) === 0 || (providers.data?.length ?? 0) === 0;

  if (noPrereqs) {
    return (
      <Notice tone="warm">
        {t("需要先创建一个 ACME 账户和一个 DNS 提供商，才能签发证书。")}
      </Notice>
    );
  }

  return (
    <div className="grid gap-4">
      <Field label={t("域名")} hint={t("主域名")}>
        <Input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" autoFocus />
      </Field>
      <Field label={t("附加域名")} hint={t("空格或逗号分隔，可含通配符")}>
        <Input value={sans} onChange={(e) => setSans(e.target.value)} placeholder="*.example.com www.example.com" />
      </Field>
      <Field label={t("ACME 账户")}>
        <Select value={accountId} onChange={(e) => setAccountId(Number(e.target.value))}>
          <option value={0}>{t("请选择…")}</option>
          {accounts.data?.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label={t("DNS 提供商")}
        hint={t("用于 DNS-01 验证。域名分散在不同厂商时可多选，每条挑战会写到拥有该 zone 的那一家")}
      >
        <div className="grid gap-1">
          {providers.data?.map((p) => (
            <label key={p.id} className="flex items-center gap-2 text-sm text-ink">
              <input
                type="checkbox"
                checked={providerIds.includes(p.id)}
                onChange={(e) =>
                  setProviderIds(
                    e.target.checked
                      ? [...providerIds, p.id]
                      : providerIds.filter((id) => id !== p.id),
                  )
                }
              />
              <span>
                {p.name} <span className="mono text-xs text-faint">({p.kind})</span>
              </span>
            </label>
          ))}
        </div>
      </Field>
      {profiles.data && Object.keys(profiles.data).length > 0 && (
        <Field
          label={t("证书类型")}
          hint={t("决定实际有效期，由 CA 提供")}
        >
          <Select value={profile} onChange={(e) => setProfile(e.target.value)}>
            <option value="">{t("使用 CA 默认")}</option>
            {Object.entries(profiles.data).map(([name, desc]) => (
              <option key={name} value={name}>
                {name} — {desc}
              </option>
            ))}
          </Select>
        </Field>
      )}

      <Field label={t("密钥算法")} hint={t("默认 ec-256；只认 RSA 的设备选 rsa-2048")}>
        <Select value={keyType} onChange={(e) => setKeyType(e.target.value)} disabled={!!csrPem.trim()}>
          {KEY_TYPES.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </Select>
      </Field>

      {advanced ? (
        <Field
          label={t("使用现成的 CSR（可选）")}
          hint={t("填了则由你自己保管私钥，服务端不会持有它。名字必须与上面完全一致")}
        >
          <Textarea
            value={csrPem}
            onChange={(e) => setCsrPem(e.target.value)}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----"
          />
        </Field>
      ) : (
        <button
          type="button"
          onClick={() => setAdvanced(true)}
          className="mono self-start text-xs text-faint hover:text-accent"
        >
          + {t("使用现成的 CSR（私钥在 HSM 等场景）")}
        </button>
      )}

      {/* Only some CAs accept a requested lifetime. Google Trust Services
          does, down to a day; Let's Encrypt rejects any order carrying
          notAfter outright, so this stays hidden unless asked for. */}
      {lifetimeOpen ? (
        <Field
          label={t("请求有效期（天）")}
          hint={t("留空用 CA 默认。仅部分 CA 支持，Let's Encrypt 会直接拒绝")}
        >
          <Input
            type="number"
            min={1}
            max={90}
            value={validityDays}
            onChange={(e) => setValidityDays(e.target.value)}
            placeholder={t("例如 7")}
          />
        </Field>
      ) : (
        <button
          type="button"
          onClick={() => setLifetimeOpen(true)}
          className="mono self-start text-xs text-faint hover:text-accent"
        >
          + {t("指定有效期天数（需 CA 支持）")}
        </button>
      )}

      <label className="flex items-start gap-2 text-sm text-ink">
        <input
          type="checkbox"
          className="mt-1"
          checked={skipDnsCheck}
          onChange={(e) => setSkipDnsCheck(e.target.checked)}
        />
        <span>
          {t("跳过 DNS 传播检查")}
          <span className="block text-xs text-muted">
            {t("本机解析器看不到该域名的记录时才勾选（内网视图等）。跳过后直接交给 CA 验证，失败会更晚才暴露。")}
          </span>
        </span>
      </label>

      {(targets.data?.length ?? 0) > 0 && (
        <div>
          <p className="mb-1.5 text-sm font-medium text-ink">{t("部署目标")}</p>
          <div className="grid gap-1.5 rounded-[9px] border border-line-strong p-3">
            {targets.data?.map((tg) => (
              <Checkbox
                key={tg.id}
                checked={targetIds.includes(tg.id)}
                onChange={() =>
                  setTargetIds((ids) => (ids.includes(tg.id) ? ids.filter((i) => i !== tg.id) : [...ids, tg.id]))
                }
                label={`${tg.name} (${tg.kind})`}
              />
            ))}
          </div>
        </div>
      )}
      {error && <Notice tone="fail">{error}</Notice>}
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>{t("取消")}</Button>
        <Button variant="accent" disabled={!ready || create.isPending} onClick={() => create.mutate()}>
          {create.isPending ? t("加载中") : t("创建")}
        </Button>
      </div>
      <p className="text-xs text-muted">{t("创建后会立即开始签发，可在详情页查看进度。")}</p>
    </div>
  );
}

function Row({ cert }: { cert: Certificate }) {
  const days = daysUntil(cert.notAfter);
  return (
    <li>
      <Link to={`/certificates/${cert.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3 hover:bg-sunk">
        {/* Two certificates for the same domain are otherwise
            indistinguishable in this list — a common state while one is
            being replaced. */}
        <span className="mono w-10 shrink-0 text-xs text-faint">#{cert.id}</span>
        <div className="min-w-0 flex-1">
          <p className="mono truncate text-sm text-ink">{cert.domain}</p>
          {cert.sans.length > 0 && (
            <p className="mono truncate text-xs text-faint">+{cert.sans.length} SAN · {cert.sans.join(" ")}</p>
          )}
        </div>
        <LifetimeBar notBefore={cert.notBefore} notAfter={cert.notAfter} />
        <span className="mono w-24 shrink-0 text-right text-xs text-muted">
          {cert.notAfter ? (days !== null && days < 0 ? t("已过期") : `${days} ${t("天")}`) : "—"}
        </span>
        <StatusPill tone={certificateTone(cert.status, cert.notAfter)} live={cert.status === "pending"} label={cert.status} />
      </Link>
      {cert.lastError && <p className="px-4 pb-2 text-xs text-fail">{cert.lastError}</p>}
    </li>
  );
}

export default function Certificates() {
  useEventInvalidate({ certificates: [["certificates"]] });
  const [params, setParams] = useSearchParams();
  const [search, setSearch] = useState(params.get("search") ?? "");
  const status = params.get("status") ?? "";
  const [creating, setCreating] = useState(false);

  const q = useQuery({
    queryKey: ["certificates", search, status],
    queryFn: () => listCertificates(search, status),
  });

  return (
    <Shell wide>
      <PageHeader
        title={t("证书")}
        subtitle={t("签发、续期与部署")}
        action={
          <Button variant="accent" onClick={() => setCreating(true)}>
            {t("新建证书")}
          </Button>
        }
      />

      <div className="mb-4 flex flex-wrap gap-2">
        <Input
          className="max-w-xs"
          placeholder={t("搜索域名…")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Select
          className="max-w-40"
          value={status}
          onChange={(e) => {
            const next = new URLSearchParams(params);
            if (e.target.value) next.set("status", e.target.value);
            else next.delete("status");
            setParams(next);
          }}
        >
          <option value="">{t("全部")}</option>
          <option value="issued">{t("已签发")}</option>
          <option value="pending">{t("待签发")}</option>
          <option value="error">{t("失败")}</option>
        </Select>
      </div>

      <Card className="overflow-hidden">
        {q.isLoading ? (
          <p className="px-4 py-10 text-center text-sm text-muted">{t("加载中")}</p>
        ) : !q.data?.length ? (
          <Empty
            title={t("还没有证书")}
            hint={t("创建一张证书后，CertCenter 会自动完成 DNS-01 验证、签发与部署。")}
            action={
              <Button variant="accent" onClick={() => setCreating(true)}>
                {t("新建证书")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-line">
            {q.data.map((c) => (
              <Row key={c.id} cert={c} />
            ))}
          </ul>
        )}
      </Card>

      {q.data && q.data.length > 0 && (
        <p className="mt-3 text-xs text-faint">
          {q.data.length} {t("张证书")} · {t("最后更新")} {formatWhen(q.data[0]?.updatedAt)}
        </p>
      )}

      <Modal open={creating} title={t("新建证书")} onClose={() => setCreating(false)}>
        <NewCertificateForm onDone={() => setCreating(false)} />
      </Modal>
    </Shell>
  );
}
