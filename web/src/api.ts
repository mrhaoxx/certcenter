export interface ApiError {
  code: string;
  message: string;
  detail?: unknown;
}

export class ApiFailure extends Error {
  constructor(
    public status: number,
    public body: ApiError,
  ) {
    super(body.message);
  }
}

async function req<T>(method: string, path: string, body?: unknown): Promise<T> {
  const resp = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (resp.status === 401 && !path.endsWith("/auth/login")) {
    window.location.href = "/login";
    throw new ApiFailure(401, { code: "UNAUTHORIZED", message: "not logged in" });
  }
  if (!resp.ok) {
    let parsed: ApiError = { code: "ERROR", message: `HTTP ${resp.status}` };
    try {
      parsed = (await resp.json()) as ApiError;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiFailure(resp.status, parsed);
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

/* ─── models ────────────────────────────────────────────────────────── */

export type CertStatus = "pending" | "issued" | "error" | "expired";

export interface Certificate {
  id: number;
  domain: string;
  sans: string[];
  acmeAccountId: number;
  dnsProviderId: number;
  dnsProviderIds?: number[];
  certPem: string | null;
  chainPem: string | null;
  serial: string | null;
  notBefore: string | null;
  notAfter: string | null;
  renewAfter: string | null;
  validityDays: number;
  profile: string;
  status: CertStatus;
  lastError: string | null;
  autoRenew: boolean;
  skipDnsCheck: boolean;
  skipDnsWaitSeconds: number | null;
  rotateKey: boolean;
  keyType: string;
  preferredChain: string;
  notBeforeDays: number;
  extendedKeyUsage: string;
  renewBeforeDays: number;
  revokedAt: string | null;
  revocationReason: string;
  csrPem: string;
  retryCount: number;
  retryAfter: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AcmeAccount {
  id: number;
  name: string;
  directoryUrl: string;
  email: string;
  accountUrl: string | null;
  validityDays: number;
  createdAt: string;
  updatedAt: string;
}

export interface NamedResource {
  id: number;
  name: string;
  kind: string;
  config: string;
  createdAt: string;
  updatedAt: string;
}

export interface Deployment {
  id: number;
  certificateId: number;
  deployTargetId: number;
  targetName: string;
  targetKind: string;
  status: "pending" | "success" | "failed";
  lastDeployedAt: string | null;
  lastError: string | null;
}

export type RunKind = "issue" | "deploy";
export type RunStatus = "running" | "success" | "error";

export interface Run {
  id: number;
  kind: RunKind;
  certificateId: number;
  deploymentId: number | null;
  attempt: number;
  trigger: string;
  status: RunStatus;
  error: string | null;
  startedAt: string;
  finishedAt: string | null;
}

export type EventLevel = "info" | "success" | "error";

export interface RunEvent {
  id: number;
  runId: number;
  seq: number;
  type: string;
  message: string;
  detail: string | null;
  level: EventLevel;
  at: string;
}

export interface OperationLog {
  id: number;
  action: string;
  resourceType: string;
  resourceId: number | null;
  detail: string | null;
  operator: string;
  createdAt: string;
}

export interface Dashboard {
  totalCertificates: number;
  issuedCertificates: number;
  expiringSoon: number;
  expired: number;
  failing: number;
  acmeAccounts: number;
  deployTargets: number;
}

export interface CertDetail {
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  signatureAlgorithm: string;
  publicKeyAlgorithm: string;
  publicKeyBits: number;
  version: number;
  subjectAltNames: string[];
  keyUsage: string[];
  extendedKeyUsage: string[];
  isCa: boolean;
  authorityKeyId: string;
  subjectKeyId: string;
  ocspServers: string[];
  issuingUrls: string[];
  crlDistributionPoints: string[];
  fingerprintSha256: string;
  fingerprintSha1: string;
  pem: string;
}

export interface X509View {
  leaf: CertDetail;
  chain: CertDetail[];
}

export interface Bundle {
  domain: string;
  certPem: string;
  chainPem: string;
  keyPem: string;
  fullchainPem: string;
}

/* ─── endpoints ─────────────────────────────────────────────────────── */

export const login = (username: string, password: string) =>
  req<{ user: string }>("POST", "/api/auth/login", { username, password });
export const logout = () => req<void>("POST", "/api/auth/logout");
export const me = () => req<{ user: string }>("GET", "/api/me");
export const changePassword = (oldPassword: string, newPassword: string) =>
  req<void>("PUT", "/api/me/password", { oldPassword, newPassword });

export const dashboard = () => req<Dashboard>("GET", "/api/dashboard");
export const logs = (limit = 100, offset = 0) =>
  req<OperationLog[]>("GET", `/api/logs?limit=${limit}&offset=${offset}`);

export const listCertificates = (search = "", status = "") => {
  const q = new URLSearchParams();
  if (search) q.set("search", search);
  if (status) q.set("status", status);
  const suffix = q.toString() ? `?${q}` : "";
  return req<Certificate[]>("GET", `/api/certificates${suffix}`);
};
export const getCertificate = (id: number) => req<Certificate>("GET", `/api/certificates/${id}`);
export const createCertificate = (body: {
  domain: string;
  sans: string[];
  acmeAccountId: number;
  dnsProviderId?: number;
  /* A certificate can span zones held at different providers. */
  dnsProviderIds?: number[];
  profile?: string;
  /* Requested lifetime in days, sent as the order's notAfter. 0 or absent
     asks for nothing — Let's Encrypt rejects any order carrying notAfter,
     so this must stay unset unless the CA is known to accept it. */
  validityDays?: number;
  /* Bypasses the DNS propagation check for this certificate only, for a
     zone the server's resolver cannot see but the CA can. */
  skipDnsCheck?: boolean;
  rotateKey?: boolean;
  keyType?: string;
  preferredChain?: string;
  notBeforeDays?: number;
  extendedKeyUsage?: string;
  renewBeforeDays?: number;
  /* A caller-supplied CSR. When set the private key never reaches the
     server, which is the point for a key that lives in an HSM. */
  csrPem?: string;
  deployTargetIds?: number[];
}) => req<Certificate>("POST", "/api/certificates", body);
export const patchCertificate = (
  id: number,
  body: {
    autoRenew?: boolean;
    profile?: string;
    /* Requested lifetime in days; 0 asks for nothing. Accepted by the API
       all along — the type simply omitted it. */
    validityDays?: number;
    skipDnsCheck?: boolean;
    skipDnsWaitSeconds?: number | null;
    rotateKey?: boolean;
    keyType?: string;
    preferredChain?: string;
    notBeforeDays?: number;
    extendedKeyUsage?: string;
    renewBeforeDays?: number;
    acmeAccountId?: number;
    dnsProviderIds?: number[];
    deployTargetIds?: number[];
  },
) => req<Certificate>("PATCH", `/api/certificates/${id}`, body);

/* An ACME profile is the only thing that actually influences the issued
   lifetime; the set is per-CA, so it is read from the directory rather
   than hard-coded. */
export const accountProfiles = (accountId: number) =>
  req<Record<string, string>>("GET", `/api/acme-accounts/${accountId}/profiles`);

export interface CaCapabilities {
  requiresEab: boolean;
  profiles: Record<string, string>;
  termsOfService: string;
  website: string;
}

/* Read what a CA advertises rather than keeping a table of it here: a CA
   can start or stop requiring external account binding, or change its
   profiles, without us shipping anything. */
export const probeDirectory = (directoryUrl: string) =>
  req<CaCapabilities>("POST", "/api/acme-directory", { directoryUrl });
export const deleteCertificate = (id: number) => req<void>("DELETE", `/api/certificates/${id}`);
export const renewCertificate = (id: number) => req<void>("POST", `/api/certificates/${id}/renew`, {});
export const deployCertificate = (id: number) => req<void>("POST", `/api/certificates/${id}/deploy`, {});
export const certificateX509 = (id: number) => req<X509View>("GET", `/api/certificates/${id}/x509`);
/* Revocation is synchronous: an operator dealing with a leaked key needs
   the outcome, not an accepted-and-see-later. */
/* Stops a run in progress. Issuance takes minutes, and before this the
   only way out was restarting the process — which left the run orphaned. */
export const cancelCertificate = (id: number) =>
  req<void>("POST", `/api/certificates/${id}/cancel`);

export const revokeCertificate = (id: number, reason: string) =>
  req<void>("POST", `/api/certificates/${id}/revoke`, { reason });

export const REVOCATION_REASONS = [
  "unspecified",
  "keyCompromise",
  "superseded",
  "cessationOfOperation",
  "affiliationChanged",
] as const;

export const KEY_TYPES = [
  "ec-256",
  "ec-384",
  "ec-521",
  "rsa-2048",
  "rsa-3072",
  "rsa-4096",
] as const;

/* PKCS#12 is a binary attachment, so it bypasses req() the way the backup
   download does. */
export async function downloadPKCS12(id: number, password: string): Promise<void> {
  const resp = await fetch(`/api/certificates/${id}/pkcs12`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!resp.ok) {
    let parsed: ApiError = { code: "ERROR", message: `HTTP ${resp.status}` };
    try {
      parsed = (await resp.json()) as ApiError;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiFailure(resp.status, parsed);
  }
  const match = /filename="([^"]+)"/.exec(resp.headers.get("Content-Disposition") ?? "");
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = match?.[1] ?? "certificate.pfx";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const certificateBundle = (id: number) => req<Bundle>("GET", `/api/certificates/${id}/bundle`);
export const certificateDeployments = (id: number) =>
  req<Deployment[]>("GET", `/api/certificates/${id}/deployments`);
export const certificateRuns = (id: number) => req<Run[]>("GET", `/api/certificates/${id}/runs`);
export const runEvents = (runId: number) => req<RunEvent[]>("GET", `/api/runs/${runId}/events`);

export const listAccounts = () => req<AcmeAccount[]>("GET", "/api/acme-accounts");
export const createAccount = (body: {
  name: string;
  directoryUrl: string;
  email: string;
  validityDays?: number;
  // Required by CAs that use external account binding (ZeroSSL, Google).
  eabKeyId?: string;
  eabMacKey?: string;
}) => req<AcmeAccount>("POST", "/api/acme-accounts", body);
export const importAccount = (body: {
  name: string;
  directoryUrl: string;
  email: string;
  accountUrl: string;
  privateKeyPem: string;
  validityDays?: number;
}) => req<AcmeAccount>("POST", "/api/acme-accounts/import", body);
export const patchAccount = (id: number, body: { name?: string; email?: string; validityDays?: number }) =>
  req<AcmeAccount>("PATCH", `/api/acme-accounts/${id}`, body);
export const deleteAccount = (id: number) => req<void>("DELETE", `/api/acme-accounts/${id}`);

export const listProviders = () => req<NamedResource[]>("GET", "/api/dns-providers");
export const createProvider = (body: { name: string; kind: string; config: string }) =>
  req<NamedResource>("POST", "/api/dns-providers", body);
export const patchProvider = (id: number, body: { name?: string; config?: string }) =>
  req<NamedResource>("PATCH", `/api/dns-providers/${id}`, body);
export const deleteProvider = (id: number) => req<void>("DELETE", `/api/dns-providers/${id}`);

export const listTargets = () => req<NamedResource[]>("GET", "/api/deploy-targets");
export const createTarget = (body: { name: string; kind: string; config: string }) =>
  req<NamedResource>("POST", "/api/deploy-targets", body);
export const patchTarget = (id: number, body: { name?: string; config?: string }) =>
  req<NamedResource>("PATCH", `/api/deploy-targets/${id}`, body);
export const deleteTarget = (id: number) => req<void>("DELETE", `/api/deploy-targets/${id}`);

/* ─── dns verification ─────────────────────────────────────────────── */

export interface DnsSettings {
  server: string;
  retries: number;
  skip: boolean;
  /* Waited blind when the check is skipped. Handing the challenge over the
     instant the record is written just moves the discovery to the CA,
     whose failure arrives later and reads worse. */
  skipWaitSeconds: number;
}

/* Stored in the database; config.toml only supplies the value before
   anything has been saved here. */
export const getDnsSettings = () => req<DnsSettings>("GET", "/api/settings/dns");
export const putDnsSettings = (body: DnsSettings) =>
  req<DnsSettings>("PUT", "/api/settings/dns", body);

export interface RestoreReport {
  manifest: {
    createdAt: string;
    acmeAccounts: number;
    dnsProviders: number;
    deployTargets: number;
    certificates: number;
  };
  rows: Record<string, number>;
  skippedColumns: string[];
}

/* Multipart because the archive is binary and can be tens of megabytes;
   base64 in JSON would inflate it for nothing. */
export async function restoreBackup(file: File, passphrase: string): Promise<RestoreReport> {
  const form = new FormData();
  form.append("archive", file);
  form.append("passphrase", passphrase);

  const resp = await fetch("/api/backup/restore", { method: "POST", body: form });
  if (!resp.ok) {
    let parsed: ApiError = { code: "ERROR", message: `HTTP ${resp.status}` };
    try {
      parsed = (await resp.json()) as ApiError;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiFailure(resp.status, parsed);
  }
  return (await resp.json()) as RestoreReport;
}

/* ─── backup ────────────────────────────────────────────────────────── */

/* The archive is a stream of bytes, not JSON, so it bypasses req(). The
   passphrase is sent per request and never stored server-side: the point
   of a user-initiated export is that the key exists only in the operator's
   head, unlike an unattended job whose key must sit on the host. */
export async function downloadBackup(passphrase: string): Promise<void> {
  const resp = await fetch("/api/backup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase }),
  });
  if (!resp.ok) {
    let parsed: ApiError = { code: "ERROR", message: `HTTP ${resp.status}` };
    try {
      parsed = (await resp.json()) as ApiError;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiFailure(resp.status, parsed);
  }

  const disposition = resp.headers.get("Content-Disposition") ?? "";
  const match = /filename="([^"]+)"/.exec(disposition);
  const name = match?.[1] ?? "certcenter-backup.tar.gz.age";

  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
