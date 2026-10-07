import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { logs } from "../api";
import { Button, Card, Empty, PageHeader, Shell, cx, formatWhen, useEventInvalidate } from "../ui";
import { t } from "../i18n";

const PAGE = 50;

/* An action's colour follows its consequence: destructive in red, anything
   that hands out key material in amber. */
function actionTone(action: string): string {
  if (action.includes("delete")) return "text-fail";
  if (action === "download") return "text-warm";
  if (action.includes("fail")) return "text-fail";
  return "text-ink";
}

export default function Logs() {
  useEventInvalidate({ logs: [["logs"]] });
  const [page, setPage] = useState(0);
  const q = useQuery({ queryKey: ["logs", page], queryFn: () => logs(PAGE, page * PAGE) });

  return (
    <Shell wide>
      <PageHeader title={t("操作日志")} subtitle={t("谁在什么时候改了什么")} />

      <Card className="overflow-hidden">
        {q.isLoading ? (
          <p className="px-4 py-10 text-center text-sm text-muted">{t("加载中")}</p>
        ) : !q.data?.length ? (
          <Empty title={t("暂无数据")} />
        ) : (
          <ul className="divide-y divide-line">
            {q.data.map((l) => (
              <li key={l.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-4 py-2.5">
                <span className={cx("mono text-xs font-medium", actionTone(l.action))}>{l.action}</span>
                <span className="mono text-xs text-faint">
                  {l.resourceType}
                  {l.resourceId !== null && `#${l.resourceId}`}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm text-muted">{l.detail ?? ""}</span>
                <span
                  className={cx(
                    "mono rounded px-1.5 py-0.5 text-[10px]",
                    l.operator === "system"
                      ? "bg-idle-soft text-muted"
                      : l.operator === "bus"
                        ? "bg-warm-soft text-warm"
                        : "bg-accent-soft text-accent",
                  )}
                >
                  {l.operator}
                </span>
                <span className="mono shrink-0 text-xs text-faint">{formatWhen(l.createdAt)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <nav className="mt-3 flex items-center justify-between">
        <Button size="sm" disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
          ‹ {t("上一页")}
        </Button>
        <span className="mono text-xs text-faint">{page + 1}</span>
        <Button size="sm" disabled={(q.data?.length ?? 0) < PAGE} onClick={() => setPage((p) => p + 1)}>
          {t("下一页")} ›
        </Button>
      </nav>
    </Shell>
  );
}
