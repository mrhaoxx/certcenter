import { useState, type FormEvent } from "react";
import { login } from "../api";
import { Button, Card, CenterPage, Field, Input, Notice } from "../ui";
import { t } from "../i18n";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await login(username, password);
      window.location.href = "/";
    } catch {
      // The API deliberately does not say which half was wrong, and neither
      // does this.
      setError(t("用户名或密码错误"));
    } finally {
      setBusy(false);
    }
  }

  return (
    <CenterPage>
      <Card className="w-full max-w-sm p-6">
        <div className="mb-6 flex items-center gap-2">
          <span className="size-7 rounded-[8px] bg-gradient-to-br from-accent to-[#a78bfa]" aria-hidden />
          <span className="mono text-base font-bold tracking-tight text-ink">CertCenter</span>
        </div>
        <form onSubmit={submit} className="grid gap-4">
          <Field label={t("用户名")}>
            <Input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
          </Field>
          <Field label={t("密码")}>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </Field>
          {error && <Notice tone="fail">{error}</Notice>}
          <Button type="submit" variant="accent" disabled={busy}>
            {busy ? t("加载中") : t("登录")}
          </Button>
        </form>
      </Card>
    </CenterPage>
  );
}
