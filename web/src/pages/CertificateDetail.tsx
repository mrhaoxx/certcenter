import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  certificateBundle,
  certificateDeployments,
  certificateRuns,
  certificateX509,
  deleteCertificate,
  deployCertificate,
  getCertificate,
  patchCertificate,
  renewCertificate,
  listTargets,
  listAccounts,
  listProviders,
  accountProfiles,
  revokeCertificate,
  cancelCertificate,
  downloadPKCS12,
  KEY_TYPES,
  REVOCATION_REASONS,
} from "../api";
import type { Certificate } from "../api";
import {
  BackLink,
  Button,
  Card,
  Checkbox,
  CopyBlock,
  CopyRow,
  Field,
  Input,
  Select,
  Modal,
  Notice,
  PageHeader,
  Shell,
  StatusPill,
  LifetimeBar,
  certificateTone,
  cx,
  daysUntil,
  formatWhen,
  useEventInvalidate,
} from "../ui";
import { Timeline } from "../components/Timeline";
import { X509View } from "../components/X509View";
import { t } from "../i18n";

type Tab = "summary" | "x509" | "timeline" | "deployments" | "settings";

export default function CertificateDetail() {
  const { id } = useParams();
  const certID = Number(id);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("summary");
  const [bundleOpen, setBundleOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [targetsOpen, setTargetsOpen] = useState(false);

  useEventInvalidate({
    // x509 parses whatever certificate is stored, so a renewal has to
    // refresh it too or the tab keeps describing the one just replaced.
    certificates: [["certificate", certID], ["x509", certID]],
    // ["run-events"] with no id is a prefix: it invalidates the events of
    // every run. The expanded one is fetched under its own key, so
    // refreshing only the run list left an open timeline frozen for the
    // whole issuance — the stretch it exists to show.
    runs: [["runs", certID], ["run-events"]],
    deployments: [["deployments", certID]],
  });

  const cert = useQuery({ queryKey: ["certificate", certID], queryFn: () => getCertificate(certID) });
  const runs = useQuery({ queryKey: ["runs", certID], queryFn: () => certificateRuns(certID) });
  const deployments = useQuery({ queryKey: ["deployments", certID], queryFn: () => certificateDeployments(certID) });
  const x509 = useQuery({
    queryKey: ["x509", certID],
    queryFn: () => certificateX509(certID),
    enabled: tab === "x509" && cert.data?.status === "issued",
    retry: false,
  });

  const renew = useMutation({
    mutationFn: () => renewCertificate(certID),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["runs", certID] }),
  });
  const deploy = useMutation({
    mutationFn: () => deployCertificate(certID),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["deployments", certID] }),
  });
  const cancel = useMutation({
    mutationFn: () => cancelCertificate(certID),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["certificate", certID] }),
  });
  const toggleAutoRenew = useMutation({
    mutationFn: (v: boolean) => patchCertificate(certID, { autoRenew: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["certificate", certID] }),
  });
  const remove = useMutation({
    mutationFn: () => deleteCertificate(certID),
    onSuccess: () => navigate("/certificates"),
  });

  if (cert.isLoading) {
    return (
      <Shell>
        <p className="text-sm text-muted">{t("加载中")}</p>
      </Shell>
    );
  }
  if (cert.error || !cert.data) {
    return (
      <Shell>
        <BackLink to="/certificates" label={t("证书")} />
        <Notice tone="fail">{t("找不到这张证书")}</Notice>
      </Shell>
    );
  }

  const c = cert.data;
  const days = daysUntil(c.notAfter);
  const issued = c.status === "issued";

  const tabs: [Tab, string][] = [
    ["summary", t("概要")],
    ["x509", t("X.509 详情")],
    ["timeline", t("时间线")],
    ["deployments", t("部署状态")],
    ["settings", t("设置")],
  ];

  return (
    <Shell wide>
      <BackLink to="/certificates" label={t("证书")} />
      <PageHeader
        title={`#${c.id} ${c.domain}`}
        subtitle={c.sans.length ? c.sans.join(" · ") : undefined}
        action={
          <div className="flex flex-wrap gap-2">
            {/* Only while something is running: issuance takes minutes,
                and the alternative used to be restarting the process,
                which left the run orphaned. */}
            {c.status === "pending" ? (
              <Button variant="danger" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
                {cancel.isPending ? t("取消中") : t("取消")}
              </Button>
            ) : (
              <Button onClick={() => renew.mutate()} disabled={renew.isPending}>
                {t("续期")}
              </Button>
            )}
            <Button onClick={() => deploy.mutate()} disabled={!issued || deploy.isPending}>
              {t("部署")}
            </Button>
            <Button onClick={() => setBundleOpen(true)} disabled={!issued}>
              {t("下载")}
            </Button>
            <Button variant="danger" onClick={() => setRevokeOpen(true)} disabled={!issued}>
              {t("吊销")}
            </Button>
            <Button variant="danger" onClick={() => remove.mutate()}>
              {t("删除")}
            </Button>
          </div>
        }
      />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <StatusPill tone={certificateTone(c.status, c.notAfter)} live={c.status === "pending"} label={c.status} />
        <LifetimeBar notBefore={c.notBefore} notAfter={c.notAfter} />
        {c.notAfter && (
          <span className="mono text-xs text-muted">
            {days !== null && days < 0 ? t("已过期") : `${days} ${t("天后到期")}`}
          </span>
        )}
        <Checkbox
          checked={c.autoRenew}
          onChange={() => toggleAutoRenew.mutate(!c.autoRenew)}
          label={t("自动续期")}
        />
      </div>


      {c.lastError && <Notice tone="fail">{c.lastError}</Notice>}
      {c.retryCount > 0 && c.retryAfter && (
        <p className="mt-2 text-xs text-warm">
          {t("已连续失败")} {c.retryCount} {t("次，下次自动重试")} {formatWhen(c.retryAfter)}
        </p>
      )}

      <nav className="mb-4 mt-6 flex gap-1 border-b border-line">
        {tabs.map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={cx(
              "-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
              tab === key ? "border-accent text-accent" : "border-transparent text-muted hover:text-ink",
            )}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "summary" && (
        <Card className="p-5">
          <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
            <div>
              <dt className="eyebrow">{t("状态")}</dt>
              <dd className="mt-0.5 text-sm text-ink">{c.status}</dd>
            </div>
            <div>
              <dt className="eyebrow">{t("有效期")}</dt>
              <dd className="mono mt-0.5 text-sm text-ink">
                {c.notBefore ? `${formatWhen(c.notBefore)} → ${formatWhen(c.notAfter)}` : "—"}
              </dd>
            </div>
            <div>
              <dt className="eyebrow">{t("序列号")}</dt>
              <dd className="mt-0.5">{c.serial ? <CopyRow value={c.serial} /> : <span className="text-faint">—</span>}</dd>
            </div>
            <div>
              <dt className="eyebrow">{t("续期时间")}</dt>
              <dd className="mono mt-0.5 text-sm text-ink">
                {c.renewAfter ? formatWhen(c.renewAfter) : t("按剩余寿命的 20% 计算")}
              </dd>
            </div>
            <div>
              <dt className="eyebrow">{t("创建时间")}</dt>
              <dd className="mono mt-0.5 text-sm text-ink">{formatWhen(c.createdAt)}</dd>
            </div>
            <div>
              <dt className="eyebrow">{t("最后更新")}</dt>
              <dd className="mono mt-0.5 text-sm text-ink">{formatWhen(c.updatedAt)}</dd>
            </div>
          </dl>
        </Card>
      )}

      {tab === "x509" && (
        <>
          {!issued ? (
            <Notice tone="warm">{t("证书尚未签发")}</Notice>
          ) : x509.isLoading ? (
            <p className="text-sm text-muted">{t("加载中")}</p>
          ) : x509.data ? (
            <X509View data={x509.data} />
          ) : (
            <Notice tone="fail">{t("无法解析证书")}</Notice>
          )}
        </>
      )}

      {tab === "timeline" && (
        <Card className="overflow-hidden">
          <Timeline runs={runs.data ?? []} />
        </Card>
      )}

      {tab === "settings" && <SettingsTab cert={c} certID={certID} />}

      {tab === "deployments" && (
        <Card className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-2">
            <p className="text-sm text-muted">{t("此证书绑定的部署目标")}</p>
            <Button size="sm" onClick={() => setTargetsOpen(true)}>
              {t("编辑")}
            </Button>
          </div>
          {!deployments.data?.length ? (
            <p className="px-4 py-10 text-center text-sm text-muted">{t("尚未绑定任何部署目标")}</p>
          ) : (
            <ul className="divide-y divide-line">
              {deployments.data.map((d) => (
                <li key={d.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                  <span className="min-w-0 flex-1">
                    <span className="text-sm text-ink">{d.targetName}</span>
                    <span className="mono ml-2 text-xs text-faint">{d.targetKind}</span>
                  </span>
                  <span className="mono text-xs text-muted">{formatWhen(d.lastDeployedAt)}</span>
                  <StatusPill
                    tone={d.status === "success" ? "run" : d.status === "failed" ? "fail" : "idle"}
                    label={d.status}
                  />
                  {d.lastError && <p className="w-full text-xs text-fail">{d.lastError}</p>}
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}

      <BundleModal open={bundleOpen} onClose={() => setBundleOpen(false)} certID={certID} />
      <RevokeModal open={revokeOpen} onClose={() => setRevokeOpen(false)} certID={certID} domain={c.domain} />
      <TargetsModal
        open={targetsOpen}
        onClose={() => setTargetsOpen(false)}
        certID={certID}
        selected={(deployments.data ?? []).map((d) => d.deployTargetId)}
      />
    </Shell>
  );
}

function BundleModal({ open, onClose, certID }: { open: boolean; onClose: () => void; certID: number }) {
  const q = useQuery({
    queryKey: ["bundle", certID],
    queryFn: () => certificateBundle(certID),
    enabled: open,
    // The bundle carries the private key, so it is never cached beyond the
    // moment it is shown.
    gcTime: 0,
    staleTime: 0,
  });

  return (
    <Modal open={open} title={t("下载证书")} onClose={onClose} wide>
      <PKCS12Row certID={certID} />
      {q.isLoading && <p className="text-sm text-muted">{t("加载中")}</p>}
      {q.error && <Notice tone="fail">{String(q.error)}</Notice>}
      {q.data && (
        <div className="grid gap-4">
          <Notice tone="warm">{t("此页包含私钥，每次查看都会记入操作日志。")}</Notice>
          <div>
            <p className="eyebrow mb-1">{t("完整链")} (fullchain.pem)</p>
            <CopyBlock value={q.data.fullchainPem} />
          </div>
          <div>
            <p className="eyebrow mb-1">{t("私钥")} (privkey.pem)</p>
            <CopyBlock value={q.data.keyPem} />
          </div>
          <div>
            <p className="eyebrow mb-1">{t("叶子证书")} (cert.pem)</p>
            <CopyBlock value={q.data.certPem} />
          </div>
          {q.data.chainPem && (
            <div>
              <p className="eyebrow mb-1">{t("中间证书")} (chain.pem)</p>
              <CopyBlock value={q.data.chainPem} />
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

function TargetsModal({
  open,
  onClose,
  certID,
  selected,
}: {
  open: boolean;
  onClose: () => void;
  certID: number;
  selected: number[];
}) {
  const targets = useQuery({ queryKey: ["targets"], queryFn: listTargets, enabled: open });
  const [ids, setIds] = useState<number[]>(selected);
  const qc = useQueryClient();

  const save = useMutation({
    mutationFn: () => patchCertificate(certID, { deployTargetIds: ids }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["deployments", certID] });
      onClose();
    },
  });

  return (
    <Modal open={open} title={t("部署目标")} onClose={onClose}>
      <div className="grid gap-3">
        {!targets.data?.length ? (
          <p className="text-sm text-muted">{t("还没有配置任何部署目标")}</p>
        ) : (
          <div className="grid gap-1.5">
            {targets.data.map((tg) => (
              <Checkbox
                key={tg.id}
                checked={ids.includes(tg.id)}
                onChange={() => setIds((v) => (v.includes(tg.id) ? v.filter((i) => i !== tg.id) : [...v, tg.id]))}
                label={`${tg.name} (${tg.kind})`}
              />
            ))}
          </div>
        )}
        <p className="text-xs text-muted">{t("已有的绑定会保留部署历史，取消勾选才会移除。")}</p>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>{t("取消")}</Button>
          <Button variant="accent" onClick={() => save.mutate()} disabled={save.isPending}>
            {t("保存")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

/* Everything about a certificate that can change after issuance.

   Domain, SANs, the ACME account and the DNS provider are deliberately
   absent: changing any of them describes a different certificate, and
   editing them in place would leave the issued material disagreeing with
   the row that produced it. Create a new certificate instead. */
function SettingsTab({ cert, certID }: { cert: Certificate; certID: number }) {
  const qc = useQueryClient();
  const [error, setError] = useState("");
  const invalidate = () => qc.invalidateQueries({ queryKey: ["certificate", certID] });

  const save = useMutation({
    mutationFn: (body: Parameters<typeof patchCertificate>[1]) => patchCertificate(certID, body),
    onSuccess: () => {
      setError("");
      invalidate();
    },
    onError: (e: Error) => setError(e.message),
  });

  const accounts = useQuery({ queryKey: ["accounts"], queryFn: listAccounts });
  const allProviders = useQuery({ queryKey: ["providers"], queryFn: listProviders });

  // Profiles are per-CA and read from its directory, so the picker shows
  // what this certificate's own account actually offers.
  const profiles = useQuery({
    queryKey: ["profiles", cert.acmeAccountId],
    queryFn: () => accountProfiles(cert.acmeAccountId),
    enabled: cert.acmeAccountId > 0,
    retry: false,
  });

  const [days, setDays] = useState(cert.validityDays ? String(cert.validityDays) : "");
  const daysChanged = (cert.validityDays || 0) !== (days ? Number(days) : 0);

  return (
    <Card className="max-w-lg p-5">
      <div className="grid gap-5">
        <Checkbox
          checked={cert.autoRenew}
          onChange={() => save.mutate({ autoRenew: !cert.autoRenew })}
          label={t("自动续期")}
        />

        <div>
          <Checkbox
            checked={cert.skipDnsCheck}
            onChange={() => save.mutate({ skipDnsCheck: !cert.skipDnsCheck })}
            label={t("跳过 DNS 传播检查")}
          />
          <p className="mt-1 text-xs text-muted">
            {t("本机解析器看不到该域名记录时才勾选（内网视图等）。跳过后改为盲等一段时间再交给 CA，等待时长见下方或全局设置。")}
          </p>
        </div>

        {profiles.data && Object.keys(profiles.data).length > 0 && (
          <Field label={t("证书类型")} hint={t("由 CA 提供；下次签发时生效")}>
            <Select
              value={cert.profile}
              onChange={(e) => save.mutate({ profile: e.target.value })}
            >
              <option value="">{t("使用 CA 默认")}</option>
              {Object.entries(profiles.data).map(([name, desc]) => (
                <option key={name} value={name}>
                  {name} — {desc}
                </option>
              ))}
            </Select>
          </Field>
        )}

        <Field
          label={t("ACME 账户")}
          hint={t("下次签发时生效；已签发的证书不受影响。换 CA 后原来的证书类型可能不存在")}
        >
          <Select
            value={cert.acmeAccountId}
            onChange={(e) => save.mutate({ acmeAccountId: Number(e.target.value) })}
          >
            {accounts.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </Select>
        </Field>

        <Field label={t("DNS 提供商")} hint={t("域名分散在不同厂商时可多选")}>
          <div className="grid gap-1">
            {allProviders.data?.map((p) => {
              const chosen = cert.dnsProviderIds ?? [];
              const on = chosen.includes(p.id);
              return (
                <label key={p.id} className="flex items-center gap-2 text-sm text-ink">
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={() => {
                      const next = on ? chosen.filter((id) => id !== p.id) : [...chosen, p.id];
                      if (next.length === 0) return; // one is required
                      save.mutate({ dnsProviderIds: next });
                    }}
                  />
                  <span>
                    {p.name} <span className="mono text-xs text-faint">({p.kind})</span>
                  </span>
                </label>
              );
            })}
          </div>
        </Field>

        <Field label={t("密钥算法")} hint={t("下次签发时生效；RSA 供只认 RSA 的设备")}>
          <Select value={cert.keyType || "ec-256"} onChange={(e) => save.mutate({ keyType: e.target.value })}>
            {KEY_TYPES.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </Select>
        </Field>

        <Checkbox
          checked={cert.rotateKey}
          onChange={() => save.mutate({ rotateKey: !cert.rotateKey })}
          label={t("续期时更换私钥")}
        />
        <p className="-mt-3 text-xs text-muted">
          {t("默认复用，与 acme.sh 一致。轮换会打断按公钥固定的东西（如 TLSA 的 SPKI selector）。")}
        </p>

        <Field
          label={t("请求有效期（天）")}
          hint={t("留空用 CA 默认。仅部分 CA 支持，Let's Encrypt 会拒绝")}
        >
          <div className="flex gap-2">
            <Input
              type="number"
              min={1}
              max={90}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              placeholder={t("例如 7")}
            />
            <Button
              disabled={!daysChanged || save.isPending}
              onClick={() => save.mutate({ validityDays: days ? Number(days) : 0 })}
            >
              {t("保存")}
            </Button>
          </div>
        </Field>

        <Field label={t("提前续期（天）")} hint={t("留空按 ARI 或剩余寿命 20%；填了则覆盖两者")}>
          <div className="flex gap-2">
            <Input
              type="number"
              min={0}
              max={365}
              defaultValue={cert.renewBeforeDays || ""}
              onBlur={(e) => {
                const v = Number(e.target.value || 0);
                if (v !== cert.renewBeforeDays) save.mutate({ renewBeforeDays: v });
              }}
              placeholder={t("例如 30")}
            />
          </div>
        </Field>

        <Field label={t("跳过检查时等待（秒）")} hint={t("留空沿用全局设置")}>
          <Input
            type="number"
            min={0}
            max={600}
            defaultValue={cert.skipDnsWaitSeconds ?? ""}
            onBlur={(e) => {
              const raw = e.target.value.trim();
              save.mutate({ skipDnsWaitSeconds: raw === "" ? null : Number(raw) });
            }}
            placeholder={t("沿用全局")}
          />
        </Field>

        <Field label={t("首选证书链")} hint={t("按签发者 CN 匹配；留空取 CA 给的第一条")}>
          <Input
            defaultValue={cert.preferredChain}
            onBlur={(e) => {
              if (e.target.value !== cert.preferredChain) save.mutate({ preferredChain: e.target.value });
            }}
            placeholder="ISRG Root X1"
          />
        </Field>

        <Field
          label={t("扩展密钥用途")}
          hint={t("逗号分隔。多数公共 CA 会忽略，自行决定证书里放什么")}
        >
          <Input
            defaultValue={cert.extendedKeyUsage}
            onBlur={(e) => {
              if (e.target.value !== cert.extendedKeyUsage) save.mutate({ extendedKeyUsage: e.target.value });
            }}
            placeholder="serverAuth,clientAuth"
          />
        </Field>

        {error && <Notice tone="fail">{error}</Notice>}

        <p className="border-t border-line pt-4 text-xs text-faint">
          {t("域名和 SAN 不可修改——改动它们就是另一张证书，请新建。ACME 账户和 DNS 提供商可以改，下次签发时生效。")}
        </p>
      </div>
    </Card>
  );
}


/* Revocation is irreversible and the certificate keeps serving traffic
   until it is replaced, so the dialog states both rather than assuming the
   operator has thought it through. */
function RevokeModal({
  open,
  onClose,
  certID,
  domain,
}: {
  open: boolean;
  onClose: () => void;
  certID: number;
  domain: string;
}) {
  const qc = useQueryClient();
  const [reason, setReason] = useState("unspecified");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const run = useMutation({
    mutationFn: () => revokeCertificate(certID, reason),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["certificate", certID] });
      setConfirm("");
      onClose();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <Modal open={open} title={t("吊销证书")} onClose={onClose}>
      <div className="grid gap-4">
        <Notice tone="fail">
          {t("吊销无法撤销。已部署的这张证书会立即失去信任，请先准备好替换。")}
        </Notice>
        <Field label={t("吊销原因")} hint={t("Let's Encrypt 只接受其中一部分")}>
          <Select value={reason} onChange={(e) => setReason(e.target.value)}>
            {REVOCATION_REASONS.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
        <Field label={t("输入域名以确认")} hint={domain}>
          <Input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={domain} />
        </Field>
        {error && <Notice tone="fail">{error}</Notice>}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>{t("取消")}</Button>
          <Button
            variant="danger"
            disabled={confirm !== domain || run.isPending}
            onClick={() => run.mutate()}
          >
            {run.isPending ? t("吊销中") : t("确认吊销")}
          </Button>
        </div>
      </div>
    </Modal>
  );
}


/* PEM is what Unix wants; Windows, IIS and Java keystores want a .pfx, and
   converting by hand means running openssl over a private key. */
function PKCS12Row({ certID }: { certID: number }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const run = useMutation({
    mutationFn: () => downloadPKCS12(certID, password),
    onSuccess: () => {
      setPassword("");
      setError("");
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <div className="mb-4 rounded border border-line p-3">
      <p className="mb-2 text-xs text-muted">
        {t("导出 PKCS#12（.pfx），供 Windows / IIS / Java keystore 使用")}
      </p>
      <div className="flex gap-2">
        <Input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={t("导出口令，至少 4 位")}
          autoComplete="new-password"
        />
        <Button disabled={password.length < 4 || run.isPending} onClick={() => run.mutate()}>
          {run.isPending ? t("导出中") : t("导出 .pfx")}
        </Button>
      </div>
      {error && (
        <div className="mt-2">
          <Notice tone="fail">{error}</Notice>
        </div>
      )}
    </div>
  );
}
