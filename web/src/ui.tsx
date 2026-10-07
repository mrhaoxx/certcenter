import {
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { Link, useLocation } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { me as fetchMe, logout } from "./api";
import { t, getLang, setLang } from "./i18n";

export function cx(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

/* Robust copy: navigator.clipboard needs a secure context, so fall back to
   execCommand for a console served over plain http behind an ingress. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

/* ─── Theme (light / dark / auto) ──────────────────────────────────── */
export type Theme = "light" | "dark" | "auto";
const themeMq = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
function resolveTheme(pref: Theme): "light" | "dark" {
  return pref === "auto" ? (themeMq?.matches ? "dark" : "light") : pref;
}
export function getThemePref(): Theme {
  return (localStorage.getItem("theme") as Theme) || "auto";
}
export function applyTheme(pref: Theme) {
  localStorage.setItem("theme", pref);
  document.documentElement.dataset.theme = resolveTheme(pref);
}
export function initTheme() {
  applyTheme(getThemePref());
  themeMq?.addEventListener("change", () => {
    if (getThemePref() === "auto") document.documentElement.dataset.theme = resolveTheme("auto");
  });
}

/* ─── Status → tone ────────────────────────────────────────────────── */
export type Tone = "run" | "warm" | "idle" | "fail";

/* certificateTone maps a certificate's state onto the colour system:
   issued is healthy, pending is in flight, error and expired are failures. */
export function certificateTone(status: string, notAfter?: string | null): Tone {
  if (status === "error") return "fail";
  if (status === "pending") return "warm";
  if (status === "issued" && notAfter) {
    const remaining = new Date(notAfter).getTime() - Date.now();
    if (remaining <= 0) return "fail";
    if (remaining <= 14 * 24 * 3600 * 1000) return "warm";
    return "run";
  }
  return status === "issued" ? "run" : "idle";
}

const toneText: Record<Tone, string> = {
  run: "text-run",
  warm: "text-warm",
  idle: "text-idle",
  fail: "text-fail",
};
const toneBg: Record<Tone, string> = {
  run: "bg-run",
  warm: "bg-warm",
  idle: "bg-idle",
  fail: "bg-fail",
};
const toneSoft: Record<Tone, string> = {
  run: "bg-run-soft",
  warm: "bg-warm-soft",
  idle: "bg-idle-soft",
  fail: "bg-fail-soft",
};

export function StatusDot({ tone, live, className }: { tone: Tone; live?: boolean; className?: string }) {
  return (
    <span
      className={cx("inline-block size-2.5 rounded-full", toneBg[tone], live && "pulse", className)}
      aria-hidden
    />
  );
}

export function StatusPill({ tone, label, live }: { tone: Tone; label: string; live?: boolean }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-semibold",
        toneSoft[tone],
        toneText[tone],
      )}
    >
      <StatusDot tone={tone} live={live} />
      {label}
    </span>
  );
}

/* Remaining-lifetime bar: the one place a certificate's health is visible
   at a glance. */
export function LifetimeBar({ notBefore, notAfter }: { notBefore?: string | null; notAfter?: string | null }) {
  if (!notBefore || !notAfter) return null;
  const start = new Date(notBefore).getTime();
  const end = new Date(notAfter).getTime();
  const now = Date.now();
  const total = end - start;
  if (total <= 0) return null;
  const elapsed = Math.min(Math.max(now - start, 0), total);
  const pct = (elapsed / total) * 100;
  const remaining = end - now;
  const tone: Tone = remaining <= 0 ? "fail" : remaining <= 14 * 24 * 3600 * 1000 ? "warm" : "run";
  return (
    <span className="inline-block h-1 w-24 overflow-hidden rounded-full bg-line align-middle" title={`${Math.round(pct)}%`}>
      <span className={cx("block h-full rounded-full", toneBg[tone])} style={{ width: `${pct}%` }} />
    </span>
  );
}

export function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  return Math.round((new Date(iso).getTime() - Date.now()) / (24 * 3600 * 1000));
}

/* ─── Buttons ──────────────────────────────────────────────────────── */
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "accent" | "ghost" | "danger";
  size?: "sm" | "md";
};
export function Button({ variant = "ghost", size = "md", className, ...rest }: BtnProps) {
  const base =
    "inline-flex items-center justify-center gap-1.5 rounded-[9px] font-medium transition-colors disabled:opacity-40 disabled:pointer-events-none";
  const sizes = { sm: "px-3 py-1.5 text-sm", md: "px-4 py-2 text-sm" };
  const variants = {
    accent: "bg-accent text-white hover:bg-accent-hi",
    ghost: "border border-line-strong bg-surface text-ink hover:border-ink/25",
    danger: "border border-fail/40 text-fail hover:bg-fail-soft",
  };
  return <button className={cx(base, sizes[size], variants[variant], className)} {...rest} />;
}

/* ─── Inputs ───────────────────────────────────────────────────────── */
const fieldBase =
  "w-full rounded-[9px] border border-line-strong bg-surface px-3 py-2 text-sm text-ink placeholder:text-faint focus:border-accent focus-visible:outline-none";

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(fieldBase, className)} {...rest} />;
}

export function Textarea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(fieldBase, "mono min-h-24 text-xs", className)} {...rest} />;
}

export function Select({ className, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cx(fieldBase, className)} {...rest} />;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 flex items-baseline justify-between gap-2">
        <span className="text-sm font-medium text-ink">{label}</span>
        {hint && <span className="text-xs text-faint">{hint}</span>}
      </span>
      {children}
    </label>
  );
}

export function Checkbox({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: () => void;
  label?: ReactNode;
}) {
  const box = (
    <span
      role="checkbox"
      aria-checked={checked}
      className={cx(
        "flex size-4 shrink-0 cursor-pointer items-center justify-center rounded-[5px] border transition-colors",
        checked ? "border-accent bg-accent" : "border-line-strong bg-surface hover:border-ink/30",
      )}
    >
      {checked && (
        <svg viewBox="0 0 10 8" className="h-2 w-2.5" aria-hidden>
          <path d="M1 4l2.6 2.6L9 1" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </span>
  );
  if (label == null) {
    return (
      <button type="button" onClick={onChange} className="inline-flex">
        {box}
      </button>
    );
  }
  return (
    <label
      className="inline-flex cursor-pointer select-none items-center gap-2"
      onClick={(e) => {
        e.preventDefault();
        onChange();
      }}
    >
      {box}
      <span className="text-sm text-ink">{label}</span>
    </label>
  );
}

/* ─── Surfaces ─────────────────────────────────────────────────────── */
export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return <section className={cx("rounded-2xl border border-line bg-surface", className)}>{children}</section>;
}

export function Notice({ tone = "fail", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <p className={cx("rounded-[9px] px-3 py-2 text-sm", toneSoft[tone], tone === "idle" ? "text-ink" : toneText[tone])}>
      {children}
    </p>
  );
}

export function Empty({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="grid place-items-center gap-2 px-4 py-14 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {hint && <p className="max-w-md text-sm text-muted">{hint}</p>}
      {action}
    </div>
  );
}

export function CopyRow({ value, label }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={async () => {
        if (await copyText(value)) {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        }
      }}
      className="group inline-flex max-w-full items-center gap-2 rounded-[9px] border border-line bg-sunk px-2.5 py-1.5 text-left transition-colors hover:border-line-strong"
      title={t("复制")}
    >
      <code className="mono min-w-0 truncate text-xs text-ink">{label ?? value}</code>
      <span className="mono shrink-0 text-[10px] uppercase tracking-wider text-faint group-hover:text-accent">
        {done ? t("已复制") : t("复制")}
      </span>
    </button>
  );
}

export function CopyBlock({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <div className="relative overflow-hidden rounded-[9px] border border-line bg-sunk">
      <button
        onClick={async () => {
          if (await copyText(value)) {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          }
        }}
        className="absolute right-2 top-2 rounded-md border border-line bg-surface px-2 py-1 text-[10px] uppercase tracking-wider text-faint transition-colors hover:text-accent"
      >
        {done ? t("已复制") : t("复制")}
      </button>
      <pre className="mono max-h-80 overflow-auto p-3 pr-16 text-xs leading-relaxed text-ink">{value}</pre>
    </div>
  );
}

/* ─── Modal ────────────────────────────────────────────────────────── */
export function Modal({
  open,
  title,
  onClose,
  children,
  wide,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
}) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/40 p-4" onClick={onClose}>
      <div
        className={cx("w-full overflow-hidden rounded-2xl border border-line bg-surface shadow-xl", wide ? "max-w-3xl" : "max-w-lg")}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-line px-5 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          <button onClick={onClose} className="text-faint hover:text-ink" aria-label={t("关闭")}>
            ✕
          </button>
        </header>
        <div className="max-h-[70vh] overflow-auto p-5">{children}</div>
      </div>
    </div>
  );
}

/* ─── App shell ────────────────────────────────────────────────────── */
function NavIcon({ kind }: { kind: "dashboard" | "certs" | "accounts" | "dns" | "targets" | "logs" }) {
  const paths: Record<string, string> = {
    dashboard: "M4 4h6v6H4zM4 12h6v6H4zM12 4h6v6h-6zM12 12h6v6h-6z",
    certs: "M11 3l7 4v8l-7 4-7-4V7z",
    accounts: "M11 4a3.5 3.5 0 110 7 3.5 3.5 0 010-7zM4 19a7 7 0 0114 0",
    dns: "M4 6h14M4 11h14M4 16h9",
    targets: "M6 4l12 7-12 7z",
    logs: "M5 4h12v14H5zM8 8h6M8 12h6",
  };
  const stroked = kind === "dns" || kind === "logs" || kind === "accounts";
  return (
    <svg width="16" height="16" viewBox="0 0 22 22" aria-hidden className="shrink-0">
      <path
        d={paths[kind]}
        fill={stroked ? "none" : "currentColor"}
        stroke={stroked ? "currentColor" : undefined}
        strokeWidth={stroked ? 1.6 : undefined}
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.9"
      />
    </svg>
  );
}

function NavItem({ to, icon, label, active }: { to: string; icon: ReactNode; label: string; active: boolean }) {
  return (
    <Link
      to={to}
      className={cx(
        "flex items-center gap-2.5 rounded-[9px] px-2.5 py-2 text-sm font-medium transition-colors",
        active ? "bg-accent-soft text-accent" : "text-muted hover:bg-sunk hover:text-ink",
      )}
    >
      {icon}
      <span className="hidden flex-1 sm:block">{label}</span>
    </Link>
  );
}

function ThemeToggle() {
  const [pref, setPref] = useState<Theme>(getThemePref());
  const opts: [Theme, string, string][] = [
    ["light", "☀", "Light"],
    ["auto", "◐", "Auto"],
    ["dark", "☾", "Dark"],
  ];
  return (
    <div className="flex flex-col items-stretch gap-0.5 rounded-lg border border-line bg-sunk p-0.5 sm:flex-row">
      {opts.map(([v, icon, label]) => (
        <button
          key={v}
          onClick={() => {
            applyTheme(v);
            setPref(v);
          }}
          title={label}
          aria-label={label}
          className={cx(
            "grid h-6 place-items-center rounded-md text-xs transition-colors sm:flex-1",
            pref === v ? "bg-surface text-accent shadow-sm" : "text-faint hover:text-ink",
          )}
        >
          {icon}
        </button>
      ))}
    </div>
  );
}

function IdentityMenu({ user }: { user?: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      {open && (
        <div className="absolute bottom-full left-0 z-50 mb-2 w-56 max-w-[calc(100vw-1.5rem)] overflow-hidden rounded-xl border border-line bg-surface shadow-lg shadow-black/20">
          <div className="border-b border-line px-4 py-3">
            <div className="mono truncate text-sm text-ink">{user ?? "…"}</div>
          </div>
          <nav className="py-1 text-sm">
            <Link to="/settings" onClick={() => setOpen(false)} className="block px-4 py-2 text-ink hover:bg-sunk">
              {t("设置")}
            </Link>
            <div className="flex items-center justify-between px-4 py-2">
              <span className="text-sm text-muted">{t("语言")}</span>
              <div className="flex gap-0.5 rounded-lg border border-line bg-sunk p-0.5">
                {(["zh", "en"] as const).map((l) => (
                  <button
                    key={l}
                    onClick={() => getLang() !== l && setLang(l)}
                    className={cx(
                      "rounded-md px-2 py-0.5 text-[11px]",
                      getLang() === l ? "bg-surface text-ink" : "text-faint hover:text-muted",
                    )}
                  >
                    {l === "zh" ? "中文" : "EN"}
                  </button>
                ))}
              </div>
            </div>
            <button
              onClick={() => logout().finally(() => (window.location.href = "/login"))}
              className="block w-full px-4 py-2 text-left text-ink hover:bg-sunk"
            >
              {t("退出登录")}
            </button>
          </nav>
        </div>
      )}
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2.5 rounded-[9px] px-2.5 py-2 text-sm hover:bg-sunk">
        <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-accent-soft text-xs font-semibold text-accent">
          {(user ?? "?").slice(0, 1).toUpperCase()}
        </span>
        <span className="mono hidden max-w-[8rem] truncate text-left text-ink sm:inline">{user ?? "…"}</span>
      </button>
    </div>
  );
}

export function Shell({ children, wide }: { children: ReactNode; wide?: boolean }) {
  const meQ = useQuery({ queryKey: ["me"], queryFn: fetchMe, retry: false });
  const loc = useLocation();
  const at = (p: string) => loc.pathname === p || (p !== "/" && loc.pathname.startsWith(p));

  return (
    <div>
      <aside className="fixed left-0 top-0 z-30 flex h-screen w-16 flex-col gap-1 border-r border-line bg-surface px-2 py-4 sm:w-56 sm:px-3">
        <Link to="/" className="mb-3 flex items-center gap-2 px-1.5">
          <span className="size-6 shrink-0 rounded-[7px] bg-gradient-to-br from-accent to-[#a78bfa]" aria-hidden />
          <span className="mono hidden text-sm font-bold tracking-tight text-ink sm:inline">CertCenter</span>
        </Link>
        <nav className="flex flex-col gap-0.5">
          <NavItem to="/" icon={<NavIcon kind="dashboard" />} label={t("概览")} active={loc.pathname === "/"} />
          <NavItem to="/certificates" icon={<NavIcon kind="certs" />} label={t("证书")} active={at("/certificates")} />
          <NavItem to="/acme-accounts" icon={<NavIcon kind="accounts" />} label={t("ACME 账户")} active={at("/acme-accounts")} />
          <NavItem to="/dns-providers" icon={<NavIcon kind="dns" />} label={t("DNS 提供商")} active={at("/dns-providers")} />
          <NavItem to="/deploy-targets" icon={<NavIcon kind="targets" />} label={t("部署目标")} active={at("/deploy-targets")} />
          <NavItem to="/logs" icon={<NavIcon kind="logs" />} label={t("操作日志")} active={at("/logs")} />
        </nav>
        <div className="mt-auto flex flex-col gap-2 border-t border-line pt-2">
          <ThemeToggle />
          <IdentityMenu user={meQ.data?.user} />
        </div>
      </aside>
      <main className="ml-16 min-w-0 sm:ml-56">
        <div className={cx("mx-auto w-full px-4 pb-16 pt-6 sm:px-8 sm:pt-10", wide ? "max-w-[100rem]" : "max-w-5xl")}>
          {children}
        </div>
      </main>
    </div>
  );
}

export function CenterPage({ children }: { children: ReactNode }) {
  return <main className="grid min-h-screen place-items-center px-4 py-10">{children}</main>;
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </header>
  );
}

export function BackLink({ to, label }: { to: string; label: string }) {
  return (
    <Link to={to} className="mono mb-3 inline-flex items-center gap-1 text-xs text-muted hover:text-accent">
      <span aria-hidden>←</span> {label}
    </Link>
  );
}

/* ─── Event-driven invalidation ────────────────────────────────────────
   One SSE connection to /api/events; a topic signal invalidates the mapped
   react-query keys, so views refresh on real changes. Issuance takes a
   minute or more — without this the UI could only poll, which is exactly
   what the previous frontend had to do. */
export function useEventInvalidate(map: Record<string, unknown[][]>) {
  const qc = useQueryClient();
  const topics = Object.keys(map).sort().join(",");
  useEffect(() => {
    if (!topics) return;
    const es = new EventSource(`/api/events?topics=${topics}`);
    for (const topic of topics.split(",")) {
      es.addEventListener(topic, () => {
        for (const key of map[topic] ?? []) qc.invalidateQueries({ queryKey: key });
      });
    }
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [topics]);
}

/* formatWhen renders a timestamp compactly; the API emits both RFC3339 and
   SQLite's "YYYY-MM-DD HH:MM:SS", so normalise before parsing. */
export function formatWhen(iso?: string | null): string {
  if (!iso) return "—";
  const normalised = iso.includes("T") ? iso : iso.replace(" ", "T") + "Z";
  const d = new Date(normalised);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
