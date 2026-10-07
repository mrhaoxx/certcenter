import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createProvider, deleteProvider, listProviders, patchProvider, type NamedResource } from "../api";
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
  formatWhen,
  useEventInvalidate,
} from "../ui";
import { t } from "../i18n";

/* Each provider kind has its own credential fields. Rendering them as real
   fields rather than a raw JSON box means the backend's validation almost
   never has to fire. The key names are the contract the backend parses. */
const KINDS: Record<
  string,
  { label: string; fields: { key: string; label: string; hint?: string; secret?: boolean; optional?: boolean }[] }
> = {
  cloudflare: {
    label: "Cloudflare",
    fields: [
      {
        key: "api_token",
        label: "API Token",
        secret: true,
        hint: t("需要 Zone:DNS:Edit；留空 Zone ID 时还需 Zone:Read"),
      },
      {
        key: "zone_id",
        label: "Zone ID",
        optional: true,
        hint: t("留空则按域名自动查找"),
      },
    ],
  },
  aliyun: {
    label: t("阿里云 DNS"),
    fields: [
      { key: "access_key_id", label: "AccessKey ID" },
      { key: "access_key_secret", label: "AccessKey Secret", secret: true },
      { key: "domain", label: t("域名"), hint: t("在阿里云托管的主域名") },
    ],
  },
};

function ConfigFields({
  kind,
  values,
  onChange,
}: {
  kind: string;
  values: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
}) {
  const spec = KINDS[kind];
  if (!spec) return null;
  return (
    <>
      {spec.fields.map((f) => (
        <Field key={f.key} label={f.optional ? `${f.label}（${t("可选")}）` : f.label} hint={f.hint}>
          <Input
            type={f.secret ? "password" : "text"}
            value={values[f.key] ?? ""}
            onChange={(e) => onChange({ ...values, [f.key]: e.target.value })}
          />
        </Field>
      ))}
    </>
  );
}

function ProviderForm({ existing, onDone }: { existing?: NamedResource; onDone: () => void }) {
  const [name, setName] = useState(existing?.name ?? "");
  const [kind, setKind] = useState(existing?.kind ?? "cloudflare");
  const [values, setValues] = useState<Record<string, string>>(() => {
    try {
      return existing ? (JSON.parse(existing.config) as Record<string, string>) : {};
    } catch {
      return {};
    }
  });
  const [error, setError] = useState("");
  const qc = useQueryClient();

  const save = useMutation({
    mutationFn: () => {
      const config = JSON.stringify(values);
      return existing
        ? patchProvider(existing.id, { name: name.trim(), config })
        : createProvider({ name: name.trim(), kind, config });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["providers"] });
      onDone();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <div className="grid gap-4">
      <Field label={t("名称")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </Field>
      <Field label={t("类型")} hint={existing ? t("类型不可修改") : undefined}>
        <Select value={kind} onChange={(e) => setKind(e.target.value)} disabled={Boolean(existing)}>
          {Object.entries(KINDS).map(([k, v]) => (
            <option key={k} value={k}>
              {v.label}
            </option>
          ))}
        </Select>
      </Field>
      <ConfigFields kind={kind} values={values} onChange={setValues} />
      {error && <Notice tone="fail">{error}</Notice>}
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>{t("取消")}</Button>
        <Button variant="accent" disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>
          {t("保存")}
        </Button>
      </div>
    </div>
  );
}

export default function DnsProviders() {
  useEventInvalidate({ providers: [["providers"]] });
  const q = useQuery({ queryKey: ["providers"], queryFn: listProviders });
  const qc = useQueryClient();
  const [editing, setEditing] = useState<NamedResource | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");

  const remove = useMutation({
    mutationFn: (id: number) => deleteProvider(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["providers"] }),
    onError: (e: Error) => setError(e.message),
  });

  return (
    <Shell>
      <PageHeader
        title={t("DNS 提供商")}
        subtitle={t("用于 DNS-01 验证的凭据")}
        action={
          <Button variant="accent" onClick={() => setCreating(true)}>
            {t("新建")}
          </Button>
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
            title={t("还没有 DNS 提供商")}
            hint={t("CertCenter 通过 DNS-01 验证域名归属，需要能写入 TXT 记录的凭据。")}
            action={
              <Button variant="accent" onClick={() => setCreating(true)}>
                {t("新建")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-line">
            {q.data.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <span className="min-w-0 flex-1 truncate text-sm text-ink">{p.name}</span>
                <span className="mono rounded bg-sunk px-1.5 py-0.5 text-xs text-muted">{p.kind}</span>
                <span className="mono text-xs text-faint">{formatWhen(p.createdAt)}</span>
                <Button size="sm" onClick={() => setEditing(p)}>
                  {t("编辑")}
                </Button>
                <Button size="sm" variant="danger" onClick={() => remove.mutate(p.id)}>
                  {t("删除")}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <p className="mt-3 text-xs text-faint">{t("被证书引用的提供商无法删除。")}</p>

      <Modal open={creating} title={t("新建 DNS 提供商")} onClose={() => setCreating(false)}>
        <ProviderForm onDone={() => setCreating(false)} />
      </Modal>
      <Modal open={Boolean(editing)} title={t("编辑 DNS 提供商")} onClose={() => setEditing(null)}>
        {editing && <ProviderForm existing={editing} onDone={() => setEditing(null)} />}
      </Modal>
    </Shell>
  );
}
