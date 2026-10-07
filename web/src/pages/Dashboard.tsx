import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { dashboard, listCertificates } from "../api";
import { Card, PageHeader, Shell, StatusPill, LifetimeBar, certificateTone, daysUntil, useEventInvalidate, cx } from "../ui";
import { t } from "../i18n";

function Stat({ label, value, tone, to }: { label: string; value: number; tone?: "fail" | "warm"; to?: string }) {
  const body = (
    <Card className={cx("p-4 transition-colors", to && "hover:border-line-strong")}>
      <p className="eyebrow">{label}</p>
      <p
        className={cx(
          "mt-1 text-2xl font-semibold tabular-nums",
          tone === "fail" && value > 0 ? "text-fail" : tone === "warm" && value > 0 ? "text-warm" : "text-ink",
        )}
      >
        {value}
      </p>
    </Card>
  );
  return to ? <Link to={to}>{body}</Link> : body;
}

export default function Dashboard() {
  useEventInvalidate({ certificates: [["dashboard"], ["certificates"]] });
  const stats = useQuery({ queryKey: ["dashboard"], queryFn: dashboard });
  const certs = useQuery({ queryKey: ["certificates", "", ""], queryFn: () => listCertificates() });

  // Surface what needs a human first: failures, then imminent expiry.
  const attention = (certs.data ?? [])
    .filter((c) => {
      if (c.status === "error") return true;
      const days = daysUntil(c.notAfter);
      return days !== null && days <= 14;
    })
    .slice(0, 8);

  return (
    <Shell>
      <PageHeader title={t("概览")} subtitle={t("证书与部署的整体状态")} />

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label={t("证书总数")} value={stats.data?.totalCertificates ?? 0} to="/certificates" />
        <Stat label={t("已签发")} value={stats.data?.issuedCertificates ?? 0} to="/certificates?status=issued" />
        <Stat label={t("即将过期")} value={stats.data?.expiringSoon ?? 0} tone="warm" />
        <Stat label={t("失败")} value={stats.data?.failing ?? 0} tone="fail" to="/certificates?status=error" />
      </div>

      <h2 className="mb-3 mt-8 text-sm font-semibold text-ink">{t("需要关注")}</h2>
      <Card className="overflow-hidden">
        {attention.length === 0 ? (
          <p className="px-4 py-10 text-center text-sm text-muted">{t("一切正常")}</p>
        ) : (
          <ul className="divide-y divide-line">
            {attention.map((c) => {
              const days = daysUntil(c.notAfter);
              return (
                <li key={c.id}>
                  <Link to={`/certificates/${c.id}`} className="flex flex-wrap items-center gap-3 px-4 py-3 hover:bg-sunk">
                    <span className="mono min-w-0 flex-1 truncate text-sm text-ink">{c.domain}</span>
                    <LifetimeBar notBefore={c.notBefore} notAfter={c.notAfter} />
                    <span className="mono w-20 text-right text-xs text-muted">
                      {days === null ? "—" : days < 0 ? t("已过期") : `${days} ${t("天")}`}
                    </span>
                    <StatusPill
                      tone={certificateTone(c.status, c.notAfter)}
                      live={c.status === "pending"}
                      label={c.status}
                    />
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </Shell>
  );
}
