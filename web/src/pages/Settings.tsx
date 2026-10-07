import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { changePassword, downloadBackup, getDnsSettings, putDnsSettings, restoreBackup } from "../api";
import type { RestoreReport } from "../api";
import type { DnsSettings } from "../api";
import { Button, Card, Checkbox, Field, Input, Notice, PageHeader, Shell } from "../ui";
import { t } from "../i18n";

const MIN_LENGTH = 8;
/* Matches backup.MinPassphraseLength on the server. The archive is a pile
   of private keys, so a guessable passphrase defeats the exercise. */
const BACKUP_MIN_LENGTH = 12;

/* Well-known DoH resolvers, offered because the default is unreachable
   from some networks and typing one from memory invites a typo that only
   shows up as a failed issuance. */
const DOH_PRESETS = [
  { label: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  { label: "Google", url: "https://dns.google/resolve" },
  { label: "阿里云", url: "https://dns.alidns.com/resolve" },
];

function DnsCard() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["dns-settings"], queryFn: getDnsSettings });
  const [draft, setDraft] = useState<{ server: string; retries: string; wait: string } | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const current = q.data;
  const server = draft?.server ?? current?.server ?? "";
  const retries = draft?.retries ?? String(current?.retries ?? "");
  const wait = draft?.wait ?? String(current?.skipWaitSeconds ?? "");

  const save = useMutation({
    mutationFn: (body: DnsSettings) => putDnsSettings(body),
    onSuccess: () => {
      setError("");
      setSaved(true);
      setDraft(null);
      qc.invalidateQueries({ queryKey: ["dns-settings"] });
    },
    onError: (e: Error) => {
      setSaved(false);
      setError(e.message);
    },
  });

  if (!current) {
    return (
      <Card className="max-w-md p-5">
        <p className="text-sm text-muted">{t("加载中")}</p>
      </Card>
    );
  }

  const dirty =
    server !== current.server ||
    retries !== String(current.retries) ||
    wait !== String(current.skipWaitSeconds);

  return (
    <Card className="max-w-md p-5">
      <h2 className="mb-1 text-sm text-ink">{t("DNS 传播检查")}</h2>
      <p className="mb-4 text-xs text-muted">
        {t("写入 TXT 记录后先自查是否可见，再交给 CA 验证，免得浪费一次验证机会。")}
      </p>

      <div className="grid gap-4">
        <Field label={t("DoH 解析器")} hint={t("必须是 https")}>
          <Input
            value={server}
            onChange={(e) => setDraft({ server: e.target.value, retries, wait })}
            placeholder="https://cloudflare-dns.com/dns-query"
          />
        </Field>
        <div className="flex flex-wrap gap-2">
          {DOH_PRESETS.map((p) => (
            <button
              key={p.url}
              type="button"
              onClick={() => setDraft({ server: p.url, retries, wait })}
              className="mono rounded border border-line px-2 py-1 text-xs text-muted hover:border-accent hover:text-accent"
            >
              {p.label}
            </button>
          ))}
        </div>

        <Field label={t("重试次数")} hint={t("每次间隔 5 秒；1–60")}>
          <Input
            type="number"
            min={1}
            max={60}
            value={retries}
            onChange={(e) => setDraft({ server, retries: e.target.value, wait })}
          />
        </Field>

        <div>
          <Checkbox
            checked={current.skip}
            onChange={() =>
              save.mutate({ ...current, skip: !current.skip })
            }
            label={t("对所有证书跳过检查")}
          />
          <p className="mt-1 text-xs text-muted">
            {t("只有单个域名看不到时，请改用证书详情页里的单证书开关，别在这里全局关掉。")}
          </p>
        </div>

        <Field
          label={t("跳过时改为等待（秒）")}
          hint={t("跳过检查时盲等这么久再交给 CA。填 0 表示不等，DNS 若未生效将由 CA 报错，更晚也更难读")}
        >
          <Input
            type="number"
            min={0}
            max={600}
            value={wait}
            onChange={(e) => setDraft({ server, retries, wait: e.target.value })}
          />
        </Field>

        {error && <Notice tone="fail">{error}</Notice>}
        {saved && !dirty && <Notice tone="run">{t("已保存，下次签发生效")}</Notice>}

        <div className="flex justify-end">
          <Button
            variant="accent"
            disabled={!dirty || save.isPending}
            onClick={() =>
              save.mutate({
                server: server.trim(),
                retries: Number(retries),
                skip: current.skip,
                skipWaitSeconds: Number(wait || 0),
              })
            }
          >
            {save.isPending ? t("保存中") : t("保存")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

/* Named "import" rather than "restore" to pair with the export above, and
   because it accepts an archive from any instance, not only this one's own
   earlier state. The button keeps the destructive wording: importing
   sounds like merging, and this replaces everything — including the admin
   password, after which logging in again needs the one from the archive's
   era. */
function ImportCard() {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [report, setReport] = useState<RestoreReport | null>(null);

  const run = useMutation({
    mutationFn: () => restoreBackup(file as File, passphrase),
    onSuccess: (r) => {
      setReport(r);
      setError("");
      setPassphrase("");
      setConfirm("");
      setFile(null);
      qc.invalidateQueries();
    },
    onError: (e: Error) => {
      setReport(null);
      setError(e.message);
    },
  });

  const ready = file !== null && passphrase.length > 0 && confirm === "RESTORE";

  return (
    <Card className="max-w-md p-5">
      <h2 className="mb-1 text-sm text-ink">{t("导入备份")}</h2>
      <p className="mb-4 text-xs text-muted">
        {t("用归档里的内容替换当前全部数据。服务无需重启，整个过程在一个事务里完成——失败则什么都不会改。")}
      </p>

      <div className="grid gap-4">
        <Notice tone="fail">
          {t("这一步无法撤销。现有的证书、账户、DNS 与部署凭据都会被覆盖，管理员密码也会变回备份时的那个。")}
        </Notice>

        <Field label={t("备份文件")} hint={t(".tar.gz.age")}>
          <input
            type="file"
            accept=".age,.gz,.tar"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="w-full text-xs text-muted file:mr-3 file:rounded file:border file:border-line file:bg-sunk file:px-2 file:py-1 file:text-xs file:text-ink"
          />
        </Field>

        <Field label={t("加密口令")}>
          <Input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="off"
          />
        </Field>

        <Field label={t("输入 RESTORE 以确认")}>
          <Input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="RESTORE" />
        </Field>

        {error && <Notice tone="fail">{error}</Notice>}
        {report && (
          <Notice tone="run">
            {t("已导入")} {report.manifest.createdAt} {t("的备份")}
            <br />
            <span className="mono text-xs">
              {Object.entries(report.rows)
                .filter(([, n]) => n > 0)
                .map(([table, n]) => `${table} ${n}`)
                .join(" · ")}
            </span>
            {report.skippedColumns.length > 0 && (
              <>
                <br />
                <span className="text-xs text-warm">
                  {t("以下字段两边对不上，未恢复：")}
                  {report.skippedColumns.join(", ")}
                </span>
              </>
            )}
          </Notice>
        )}

        <div className="flex justify-end">
          <Button variant="danger" disabled={!ready || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? t("导入中") : t("覆盖当前数据")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function BackupCard() {
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const mismatch = confirm.length > 0 && passphrase !== confirm;
  const tooShort = passphrase.length > 0 && passphrase.length < BACKUP_MIN_LENGTH;

  const run = useMutation({
    mutationFn: () => downloadBackup(passphrase),
    onSuccess: () => {
      setDone(true);
      setPassphrase("");
      setConfirm("");
      setError("");
    },
    onError: (e: Error) => {
      setDone(false);
      setError(e.message);
    },
  });

  return (
    <Card className="max-w-md p-5">
      <h2 className="mb-1 text-sm text-ink">{t("导出备份")}</h2>
      <p className="mb-4 text-xs text-muted">
        {t("包含 ACME 账户私钥、DNS 与部署凭据、证书私钥。丢失后只能逐个重新申请和录入。")}
      </p>

      <div className="grid gap-4">
        <Field label={t("加密口令")} hint={t("至少 12 位；服务端不保存，忘了就解不开")}>
          <Input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            autoComplete="new-password"
          />
        </Field>
        <Field label={t("再输一次")}>
          <Input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
        </Field>

        {tooShort && <Notice tone="warm">{t("口令至少 12 位")}</Notice>}
        {mismatch && <Notice tone="warm">{t("两次输入不一致")}</Notice>}
        {error && <Notice tone="fail">{error}</Notice>}
        {done && (
          <Notice tone="run">
            {t("已下载。用 age 解开：")}
            <br />
            <span className="mono text-xs">age -d 备份文件 | tar -xz</span>
          </Notice>
        )}

        <div className="flex justify-end">
          <Button
            variant="accent"
            disabled={
              run.isPending ||
              passphrase.length < BACKUP_MIN_LENGTH ||
              passphrase !== confirm
            }
            onClick={() => run.mutate()}
          >
            {run.isPending ? t("导出中") : t("下载加密备份")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default function Settings() {
  const [oldPassword, setOld] = useState("");
  const [newPassword, setNew] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  const change = useMutation({
    mutationFn: () => changePassword(oldPassword, newPassword),
    onSuccess: () => {
      setDone(true);
      setError("");
      setOld("");
      setNew("");
      setConfirm("");
    },
    onError: (e: Error) => {
      setDone(false);
      setError(e.message);
    },
  });

  const mismatch = confirm.length > 0 && confirm !== newPassword;
  const tooShort = newPassword.length > 0 && newPassword.length < MIN_LENGTH;
  const ready = oldPassword && newPassword.length >= MIN_LENGTH && confirm === newPassword;

  return (
    <Shell>
      <PageHeader title={t("设置")} />

      <div className="grid gap-4">

      <Card className="max-w-md p-5">
        <h2 className="mb-4 text-sm font-semibold text-ink">{t("修改密码")}</h2>
        <div className="grid gap-4">
          <Field label={t("当前密码")}>
            <Input type="password" value={oldPassword} onChange={(e) => setOld(e.target.value)} autoComplete="current-password" />
          </Field>
          <Field label={t("新密码")} hint={`${t("至少")} ${MIN_LENGTH} ${t("位")}`}>
            <Input type="password" value={newPassword} onChange={(e) => setNew(e.target.value)} autoComplete="new-password" />
          </Field>
          <Field label={t("确认新密码")}>
            <Input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
          </Field>

          {tooShort && <Notice tone="warm">{`${t("新密码至少需要")} ${MIN_LENGTH} ${t("位")}`}</Notice>}
          {mismatch && <Notice tone="warm">{t("两次输入的新密码不一致")}</Notice>}
          {error && <Notice tone="fail">{error}</Notice>}
          {done && <Notice tone="run">{t("密码已修改，下次登录请使用新密码。")}</Notice>}

          <Button variant="accent" disabled={!ready || change.isPending} onClick={() => change.mutate()}>
            {change.isPending ? t("加载中") : t("修改密码")}
          </Button>
        </div>
        <p className="mt-4 text-xs text-muted">
          {t("密码保存在数据库中，修改后立即生效，无需重启服务。")}
        </p>
      </Card>
        <DnsCard />
        <BackupCard />
        <ImportCard />
      </div>
    </Shell>
  );
}