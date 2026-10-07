import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { runEvents, type Run, type RunEvent, type EventLevel } from "../api";
import { cx, StatusPill, formatWhen, type Tone } from "../ui";
import { t } from "../i18n";

/* One timeline renders both issuance and deployment runs. That is the
   direct payoff of merging the schema's two near-identical event tables:
   the previous UI needed a separate component per table. */

const levelTone: Record<EventLevel, Tone> = { info: "idle", success: "run", error: "fail" };

function runTone(run: Run): Tone {
  if (run.status === "running") return "warm";
  if (run.status === "error") return "fail";
  return "run";
}

function runLabel(run: Run): string {
  const kind = run.kind === "issue" ? t("签发") : t("部署");
  return `${kind} #${run.attempt}`;
}

function EventRow({ event }: { event: RunEvent }) {
  const [open, setOpen] = useState(false);
  const tone = levelTone[event.level];
  const hasDetail = Boolean(event.detail);

  return (
    <li className="relative pl-6">
      {/* The rail dot sits on the vertical line drawn by the parent. */}
      <span
        className={cx(
          "absolute left-[7px] top-[7px] size-[7px] rounded-full ring-2 ring-surface",
          tone === "run" ? "bg-run" : tone === "fail" ? "bg-fail" : "bg-idle",
        )}
        aria-hidden
      />
      <div className="pb-3">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="mono text-[10px] uppercase tracking-wider text-faint">{event.type}</span>
          <span className={cx("text-sm", event.level === "error" ? "text-fail" : "text-ink")}>{event.message}</span>
          <span className="mono ml-auto shrink-0 text-[11px] text-faint">{formatWhen(event.at)}</span>
        </div>
        {hasDetail && (
          <>
            <button
              onClick={() => setOpen((v) => !v)}
              className="mono mt-1 text-[11px] text-faint hover:text-accent"
            >
              {open ? t("收起详情") : t("展开详情")}
            </button>
            {open && (
              <pre className="mono mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded-[9px] border border-line bg-sunk p-2.5 text-[11px] leading-relaxed text-muted">
                {event.detail}
              </pre>
            )}
          </>
        )}
      </div>
    </li>
  );
}

function RunEvents({ runId }: { runId: number }) {
  const q = useQuery({ queryKey: ["run-events", runId], queryFn: () => runEvents(runId) });

  if (q.isLoading) return <p className="px-4 py-3 text-sm text-muted">{t("加载中")}</p>;
  if (q.error) return <p className="px-4 py-3 text-sm text-fail">{String(q.error)}</p>;
  if (!q.data?.length) return <p className="px-4 py-3 text-sm text-muted">{t("暂无事件")}</p>;

  return (
    <ol className="relative ml-4 border-l border-line py-3 pl-0">
      {q.data.map((e) => (
        <EventRow key={e.id} event={e} />
      ))}
    </ol>
  );
}

export function Timeline({ runs }: { runs: Run[] }) {
  // The newest run is the one an operator is almost always looking at.
  const [expanded, setExpanded] = useState<number | null>(runs[0]?.id ?? null);
  // useState only seeds once, so a run started while the page is open left
  // the previous — and finished — one expanded while the live one scrolled
  // in above it. Following the newest is dropped as soon as the operator
  // picks a run themselves, since then they are reading something specific.
  const [pinned, setPinned] = useState(false);
  const newest = runs[0]?.id ?? null;
  useEffect(() => {
    if (!pinned) setExpanded(newest);
  }, [newest, pinned]);

  if (!runs.length) {
    return <p className="px-4 py-6 text-center text-sm text-muted">{t("还没有任何运行记录")}</p>;
  }

  return (
    <div className="divide-y divide-line">
      {runs.map((run) => {
        const open = expanded === run.id;
        return (
          <div key={run.id}>
            <button
              onClick={() => {
                setPinned(true);
                setExpanded(open ? null : run.id);
              }}
              className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-sunk"
            >
              <span className={cx("text-faint transition-transform", open && "rotate-90")} aria-hidden>
                ›
              </span>
              <span className="text-sm font-medium text-ink">{runLabel(run)}</span>
              <StatusPill
                tone={runTone(run)}
                live={run.status === "running"}
                label={
                  run.status === "running" ? t("进行中") : run.status === "error" ? t("失败") : t("成功")
                }
              />
              <span className="mono text-[11px] text-faint">{run.trigger}</span>
              <span className="mono ml-auto text-[11px] text-faint">{formatWhen(run.startedAt)}</span>
            </button>
            {run.error && !open && (
              <p className="px-4 pb-3 pl-11 text-xs text-fail">{run.error}</p>
            )}
            {open && <RunEvents runId={run.id} />}
          </div>
        );
      })}
    </div>
  );
}
