import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createTarget, deleteTarget, listTargets, patchTarget, type NamedResource } from "../api";
import {
  Button,
  Card,
  Empty,
  Field,
  Input,
  Modal,
  Notice,
  PageHeader,
  Shell,
  formatWhen,
  useEventInvalidate,
} from "../ui";
import { PipelineEditor, parsePipeline, serialisePipeline, type PipelineStep } from "../components/PipelineEditor";
import { t } from "../i18n";

/* There is one kind now. Webhook, the config center and the CDNs were
   kinds of their own, which let a target do exactly one of them; they are
   steps, and a target is the ordered list. */
const KIND = "pipeline";

/* A one-line description of what a pipeline does, for the list. */
function summarise(config: string): string {
  const steps = parsePipeline(config);
  if (steps.length === 0) return t("（空）");
  const types = steps.map((s) => s.type);
  const shown = types.slice(0, 4).join(" → ");
  return types.length > 4 ? `${shown} → …（共 ${types.length} 步）` : shown;
}

function TargetForm({ existing, onDone }: { existing?: NamedResource; onDone: () => void }) {
  const [name, setName] = useState(existing?.name ?? "");
  const [steps, setSteps] = useState<PipelineStep[]>(() => (existing ? parsePipeline(existing.config) : []));
  const [error, setError] = useState("");
  const qc = useQueryClient();

  const save = useMutation({
    mutationFn: () => {
      const config = serialisePipeline(steps);
      return existing
        ? patchTarget(existing.id, { name: name.trim(), config })
        : createTarget({ name: name.trim(), kind: KIND, config });
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["targets"] });
      onDone();
    },
    onError: (e: Error) => setError(e.message),
  });

  return (
    <div className="grid gap-4">
      <Field label={t("名称")}>
        <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
      </Field>

      <PipelineEditor steps={steps} onChange={setSteps} />

      {error && <Notice tone="fail">{error}</Notice>}
      <div className="flex justify-end gap-2">
        <Button onClick={onDone}>{t("取消")}</Button>
        <Button
          variant="accent"
          disabled={!name.trim() || steps.length === 0 || save.isPending}
          onClick={() => save.mutate()}
        >
          {t("保存")}
        </Button>
      </div>
    </div>
  );
}

export default function DeployTargets() {
  useEventInvalidate({ targets: [["targets"]] });
  const q = useQuery({ queryKey: ["targets"], queryFn: listTargets });
  const qc = useQueryClient();
  const [editing, setEditing] = useState<NamedResource | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");

  const remove = useMutation({
    mutationFn: (id: number) => deleteTarget(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
    onError: (e: Error) => setError(e.message),
  });

  return (
    <Shell wide>
      <PageHeader
        title={t("部署目标")}
        subtitle={t("证书签发后自动安装到这些地方")}
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
            title={t("还没有部署目标")}
            hint={t("配置后，每次签发和续期都会自动把证书安装到目标上。")}
            action={
              <Button variant="accent" onClick={() => setCreating(true)}>
                {t("新建")}
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-line">
            {q.data.map((tg) => (
              <li key={tg.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <span className="min-w-0 flex-1 truncate text-sm text-ink">{tg.name}</span>
                {/* Every target is a pipeline, so the kind says nothing.
                    What it does is the useful summary. */}
                <span className="mono truncate text-xs text-muted">{summarise(tg.config)}</span>
                <span className="mono text-xs text-faint">{formatWhen(tg.createdAt)}</span>
                <Button size="sm" onClick={() => setEditing(tg)}>
                  {t("编辑")}
                </Button>
                <Button size="sm" variant="danger" onClick={() => remove.mutate(tg.id)}>
                  {t("删除")}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <p className="mt-3 text-xs text-faint">{t("仍被证书绑定的目标无法删除。")}</p>

      <Modal open={creating} title={t("新建部署目标")} onClose={() => setCreating(false)} wide>
        <TargetForm onDone={() => setCreating(false)} />
      </Modal>
      <Modal open={Boolean(editing)} title={t("编辑部署目标")} onClose={() => setEditing(null)} wide>
        {editing && <TargetForm existing={editing} onDone={() => setEditing(null)} />}
      </Modal>
    </Shell>
  );
}
