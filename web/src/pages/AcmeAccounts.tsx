import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createAccount, deleteAccount, importAccount, listAccounts, probeDirectory } from "../api";
import {
  Button,
  Card,
  Empty,
  Field,
  Input,
  Modal,
  Notice,
  PageHeader,
  Select,
  Shell,
  Textarea,
  formatWhen,
  useEventInvalidate,
} from "../ui";
import { t } from "../i18n";

/* Display names only. Whether a CA needs external account binding is read
   from its directory at runtime (externalAccountRequired), not listed here
   — a hard-coded table drifts the moment a CA changes its mind.

   requiresEmail stays local because no directory field advertises it:
   Google answers "Accounts must have at least one contact", verified
   against its API. ZeroSSL is absent deliberately — it rejects on EAB
   before any contact check, so whether it demands one is untested, and
   guessing would block a configuration that may be fine. */
const DIRECTORIES = [
  { label: "Let's Encrypt", url: "https://acme-v02.api.letsencrypt.org/directory" },
  { label: "Let's Encrypt (staging)", url: "https://acme-staging-v02.api.letsencrypt.org/directory" },
  { label: "ZeroSSL", url: "https://acme.zerossl.com/v2/DV90" },
  { label: "Google Trust Services", url: "https://dv.acme-v02.api.pki.goog/directory" },
  {
    label: "Google Trust Services (staging，证书不受信任)",
    url: "https://dv.acme-v02.test-api.pki.goog/directory",
  },
];

const REQUIRES_EMAIL = new Set([
  "https://dv.acme-v02.api.pki.goog/directory",
  "https://dv.acme-v02.test-api.pki.goog/directory",
]);

/* Where each CA hands out its EAB credentials. Without this the operator
   has to go hunting, and the two fields below look like arbitrary
   secrets. */
const EAB_SOURCE: Record<string, string> = {
  "https://acme.zerossl.com/v2/DV90": "ZeroSSL 控制台 → Developer → EAB Credentials",
  "https://dv.acme-v02.api.pki.goog/directory": "gcloud publicca external-account-keys create",
  // The staging environment issues its own EAB keys, and reaching them
  // means repointing gcloud at the preprod endpoint first — not a flag on
  // the create command.
  "https://dv.acme-v02.test-api.pki.goog/directory":
    "gcloud config set api_endpoint_overrides/publicca https://preprod-publicca.googleapis.com/ && gcloud publicca external-account-keys create",
};

function CreateForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [directoryUrl, setDirectoryUrl] = useState(DIRECTORIES[0].url);
  const [email, setEmail] = useState("");
  const [eabKeyId, setEabKeyId] = useState("");
  const [eabMacKey, setEabMacKey] = useState("");
  const [error, setError] = useState("");
  const qc = useQueryClient();

  // Show the EAB fields when the chosen CA is known to need them, and keep
  // them available for any other directory the operator types in.
  // Ask the CA what it needs. While the probe is in flight the EAB fields
  // stay hidden rather than guessed at.
  const caps = useQuery({
    queryKey: ["ca-capabilities", directoryUrl],
    queryFn: () => probeDirectory(directoryUrl),
    enabled: directoryUrl.startsWith("https://"),
    retry: false,
    staleTime: 5 * 60 * 1000,
  });
  const needsEab = caps.data?.requiresEab ?? false;
  const needsEmail = REQUIRES_EMAIL.has(directoryUrl);
  const [eabOpen, setEabOpen] = useState(false);
  const showEab = needsEab || eabOpen;

  const create = useMutation({
    mutationFn: () =>
      createAccount({
        name: name.trim(),
        directoryUrl,
        email: email.trim(),
        eabKeyId: eabKeyId.trim() || undefined,
        eabMacKey: eabMacKey.trim() || undefined,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
      onDone();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <div className="grid gap-4">
      <Field label={t("名称")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="letsencrypt" autoFocus />
      </Field>
      <Field label={t("目录地址")}>
        <Select value={directoryUrl} onChange={(e) => setDirectoryUrl(e.target.value)}>
          {DIRECTORIES.map((d) => (
            <option key={d.url} value={d.url}>
              {d.label}
            </option>
          ))}
        </Select>
      </Field>
      <Field label={t("目录地址")} hint={t("也可直接填写其他 CA")}>
        <Input value={directoryUrl} onChange={(e) => setDirectoryUrl(e.target.value)} />
      </Field>
      {/* Let's Encrypt stopped sending expiration notices on 2025-06-04, so
          the contact address no longer buys the reminder it used to. It stays
          because some CAs still require one. */}
      <Field
        label={needsEmail ? t("邮箱") : t("邮箱（可选）")}
        hint={
          needsEmail
            ? t("这家 CA 要求必须填写联系邮箱")
            : t("Let's Encrypt 已停发到期提醒；部分 CA 仍要求填写")
        }
      >
        <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="admin@example.com" />
      </Field>

      {showEab ? (
        <>
          {needsEab && (
            <Notice tone="warm">
              {t("这家 CA 要求外部账户绑定，请填入它给你的凭据。")}
              {EAB_SOURCE[directoryUrl] && (
                <>
                  <br />
                  <span className="mono text-xs">{EAB_SOURCE[directoryUrl]}</span>
                </>
              )}
            </Notice>
          )}
          <Field label={t("EAB Key ID")} hint="kid">
            <Input value={eabKeyId} onChange={(e) => setEabKeyId(e.target.value)} />
          </Field>
          <Field label={t("EAB HMAC Key")} hint={t("base64 编码，带不带填充都行")}>
            <Input type="password" value={eabMacKey} onChange={(e) => setEabMacKey(e.target.value)} />
          </Field>
        </>
      ) : (
        <button
          type="button"
          onClick={() => setEabOpen(true)}
          className="mono self-start text-xs text-faint hover:text-accent"
        >
          + {t("这家 CA 需要外部账户绑定 (EAB)")}
        </button>
      )}

      {error && <Notice tone="fail">{error}</Notice>}
      <p className="text-xs text-muted">{t("创建时会立即向 CA 注册，失败则不会留下半成品记录。")}</p>
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>{t("取消")}</Button>
        <Button
          variant="accent"
          disabled={
            !name.trim() ||
            create.isPending ||
            (needsEmail && !email.trim()) ||
            (needsEab && (!eabKeyId.trim() || !eabMacKey.trim()))
          }
          onClick={() => create.mutate()}
        >
          {create.isPending ? t("加载中") : t("创建")}
        </Button>
      </div>
    </div>
  );
}

function ImportForm({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("");
  const [directoryUrl, setDirectoryUrl] = useState(DIRECTORIES[0].url);
  const [email, setEmail] = useState("");
  const [accountUrl, setAccountUrl] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [error, setError] = useState("");
  const qc = useQueryClient();

  const run = useMutation({
    mutationFn: () =>
      importAccount({
        name: name.trim(),
        directoryUrl,
        email: email.trim(),
        accountUrl: accountUrl.trim(),
        privateKeyPem,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["accounts"] });
      onDone();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <div className="grid gap-4">
      <Field label={t("名称")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </Field>
      <Field label={t("目录地址")}>
        <Input value={directoryUrl} onChange={(e) => setDirectoryUrl(e.target.value)} />
      </Field>
      <Field label={t("邮箱（可选）")}>
        <Input value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label={t("账户 URL")} hint="kid">
        <Input
          value={accountUrl}
          onChange={(e) => setAccountUrl(e.target.value)}
          placeholder="https://acme-v02.api.letsencrypt.org/acme/acct/12345"
        />
      </Field>
      <Field label={t("账户私钥")} hint="PKCS#8 PEM">
        <Textarea
          value={privateKeyPem}
          onChange={(e) => setPrivateKeyPem(e.target.value)}
          placeholder="-----BEGIN PRIVATE KEY-----"
        />
      </Field>
      {error && <Notice tone="fail">{error}</Notice>}
      <p className="text-xs text-muted">{t("导入时会向 CA 校验这对密钥与账户 URL 是否有效。")}</p>
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>{t("取消")}</Button>
        <Button
          variant="accent"
          disabled={!name.trim() || !accountUrl.trim() || !privateKeyPem.trim() || run.isPending}
          onClick={() => run.mutate()}
        >
          {run.isPending ? t("加载中") : t("导入")}
        </Button>
      </div>
    </div>
  );
}

export default function AcmeAccounts() {
  useEventInvalidate({ accounts: [["accounts"]] });
  const q = useQuery({ queryKey: ["accounts"], queryFn: listAccounts });
  const qc = useQueryClient();
  const [mode, setMode] = useState<"none" | "create" | "import">("none");
  const [error, setError] = useState("");

  const remove = useMutation({
    mutationFn: (id: number) => deleteAccount(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["accounts"] }),
    onError: (e: Error) => setError(e.message),
  });

  return (
    <Shell>
      <PageHeader
        title={t("ACME 账户")}
        subtitle={t("向证书颁发机构标识自己的身份")}
        action={
          <div className="flex gap-2">
            <Button onClick={() => setMode("import")}>{t("导入")}</Button>
            <Button variant="accent" onClick={() => setMode("create")}>
              {t("新建")}
            </Button>
          </div>
        }
      />

      {error && (
        <div className="mb-3">
          <Notice tone="fail">{error}</Notice>
        </div>
      )}

      <Card className="overflow-hidden">
        {q.isLoading ? (
          <p className="px-4 py-10 text-center text-sm text-muted">{t("加载中")}</p>
        ) : !q.data?.length ? (
          <Empty
            title={t("还没有 ACME 账户")}
            hint={t("签发证书前需要先在证书颁发机构注册一个账户。")}
            action={
              <Button variant="accent" onClick={() => setMode("create")}>
                {t("新建")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-line">
            {q.data.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-ink">{a.name}</p>
                  <p className="mono truncate text-xs text-faint">{a.directoryUrl}</p>
                </div>
                <span className="mono text-xs text-muted">{a.email || "—"}</span>
                <span className="mono text-xs text-faint">{formatWhen(a.createdAt)}</span>
                <Button size="sm" variant="danger" onClick={() => remove.mutate(a.id)}>
                  {t("删除")}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <p className="mt-3 text-xs text-faint">{t("账户私钥保存在服务端，任何接口都不会返回它。")}</p>

      <Modal open={mode === "create"} title={t("新建 ACME 账户")} onClose={() => setMode("none")}>
        <CreateForm onDone={() => setMode("none")} />
      </Modal>
      <Modal open={mode === "import"} title={t("导入 ACME 账户")} onClose={() => setMode("none")}>
        <ImportForm onDone={() => setMode("none")} />
      </Modal>
    </Shell>
  );
}
