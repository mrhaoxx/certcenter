import { type CertDetail, type X509View as X509Data } from "../api";
import { CopyBlock, CopyRow, formatWhen } from "../ui";
import { t } from "../i18n";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-1 py-2 sm:grid-cols-[11rem_1fr] sm:gap-3">
      <dt className="text-xs font-medium text-faint sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 text-sm text-ink">{children}</dd>
    </div>
  );
}

function List({ values }: { values: string[] }) {
  if (!values.length) return <span className="text-faint">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {values.map((v) => (
        <span key={v} className="mono rounded bg-sunk px-1.5 py-0.5 text-xs text-ink">
          {v}
        </span>
      ))}
    </div>
  );
}

/* Fingerprints are long hex; grouping them in pairs makes them scannable
   against what a browser or openssl prints. */
function fingerprint(hex: string): string {
  return (hex.match(/.{1,2}/g) ?? []).join(":").toUpperCase();
}

function CertPanel({ cert, title }: { cert: CertDetail; title: string }) {
  return (
    <section className="rounded-2xl border border-line bg-surface">
      <header className="border-b border-line px-5 py-3">
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
        <p className="mono mt-0.5 truncate text-xs text-muted">{cert.subject || t("（空主题，域名在 SAN 中）")}</p>
      </header>
      <dl className="divide-y divide-line px-5 py-1">
        <Row label={t("颁发者")}>
          <span className="mono text-xs">{cert.issuer}</span>
        </Row>
        <Row label={t("序列号")}>
          <CopyRow value={cert.serialNumber} />
        </Row>
        <Row label={t("有效期")}>
          <span className="mono text-xs">
            {formatWhen(cert.notBefore)} → {formatWhen(cert.notAfter)}
          </span>
        </Row>
        <Row label={t("域名 (SAN)")}>
          <List values={cert.subjectAltNames} />
        </Row>
        <Row label={t("公钥")}>
          <span className="mono text-xs">
            {cert.publicKeyAlgorithm}
            {cert.publicKeyBits > 0 && ` ${cert.publicKeyBits} bit`}
          </span>
        </Row>
        <Row label={t("签名算法")}>
          <span className="mono text-xs">{cert.signatureAlgorithm}</span>
        </Row>
        <Row label={t("密钥用途")}>
          <List values={cert.keyUsage} />
        </Row>
        <Row label={t("扩展密钥用途")}>
          <List values={cert.extendedKeyUsage} />
        </Row>
        {cert.ocspServers.length > 0 && (
          <Row label="OCSP">
            <List values={cert.ocspServers} />
          </Row>
        )}
        {cert.crlDistributionPoints.length > 0 && (
          <Row label="CRL">
            <List values={cert.crlDistributionPoints} />
          </Row>
        )}
        <Row label="SHA-256">
          <CopyRow value={cert.fingerprintSha256} label={fingerprint(cert.fingerprintSha256)} />
        </Row>
        <Row label="SHA-1">
          <CopyRow value={cert.fingerprintSha1} label={fingerprint(cert.fingerprintSha1)} />
        </Row>
        <Row label="PEM">
          <CopyBlock value={cert.pem} />
        </Row>
      </dl>
    </section>
  );
}

export function X509View({ data }: { data: X509Data }) {
  return (
    <div className="grid gap-4">
      <CertPanel cert={data.leaf} title={t("叶子证书")} />
      {/* The chain never repeats the leaf: cert_pem holds the leaf alone and
          chain_pem the intermediates. */}
      {data.chain.map((c, i) => (
        <CertPanel key={c.fingerprintSha256} cert={c} title={`${t("中间证书")} ${i + 1}`} />
      ))}
    </div>
  );
}
