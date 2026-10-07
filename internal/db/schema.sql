CREATE TABLE IF NOT EXISTS acme_accounts (
  id            INTEGER PRIMARY KEY,
  name          TEXT    NOT NULL,
  directory_url TEXT    NOT NULL,
  email         TEXT    NOT NULL,
  account_url   TEXT,
  private_key   TEXT    NOT NULL,
  validity_days INTEGER NOT NULL DEFAULT 90,
  created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dns_providers (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,
  config     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS certificates (
  id              INTEGER PRIMARY KEY,
  domain          TEXT    NOT NULL,
  sans            TEXT    NOT NULL DEFAULT '[]',
  acme_account_id INTEGER NOT NULL REFERENCES acme_accounts(id),
  dns_provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  cert_pem        TEXT,
  chain_pem       TEXT,
  key_pem         TEXT,
  serial          TEXT,
  not_before      TEXT,
  not_after       TEXT,
  renew_after     TEXT,
  validity_days   INTEGER NOT NULL DEFAULT 0,
  profile         TEXT    NOT NULL DEFAULT '',
  status          TEXT    NOT NULL DEFAULT 'pending',
  last_error      TEXT,
  auto_renew      INTEGER NOT NULL DEFAULT 1,
  skip_dns_check  INTEGER NOT NULL DEFAULT 0,
  skip_dns_wait_seconds INTEGER,
  rotate_key      INTEGER NOT NULL DEFAULT 0,
  key_type        TEXT    NOT NULL DEFAULT '',
  preferred_chain TEXT    NOT NULL DEFAULT '',
  not_before_days INTEGER NOT NULL DEFAULT 0,
  extended_key_usage TEXT NOT NULL DEFAULT '',
  renew_before_days  INTEGER NOT NULL DEFAULT 0,
  revoked_at         TEXT,
  revocation_reason  TEXT NOT NULL DEFAULT '',
  csr_pem            TEXT NOT NULL DEFAULT '',
  retry_count     INTEGER NOT NULL DEFAULT 0,
  retry_after     TEXT,
  created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
  updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- A certificate can span zones held at different providers, so the
-- relationship is many-to-many. certificates.dns_provider_id survives as
-- the seed for this table and to satisfy its NOT NULL; issuance reads
-- only from here.
CREATE TABLE IF NOT EXISTS certificate_dns_providers (
  certificate_id  INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  dns_provider_id INTEGER NOT NULL REFERENCES dns_providers(id),
  PRIMARY KEY (certificate_id, dns_provider_id)
);

CREATE TABLE IF NOT EXISTS deploy_targets (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,
  config     TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS deployments (
  id               INTEGER PRIMARY KEY,
  certificate_id   INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deploy_target_id INTEGER NOT NULL REFERENCES deploy_targets(id) ON DELETE CASCADE,
  status           TEXT    NOT NULL DEFAULT 'pending',
  last_deployed_at TEXT,
  last_error       TEXT,
  UNIQUE(certificate_id, deploy_target_id)
);

CREATE TABLE IF NOT EXISTS runs (
  id             INTEGER PRIMARY KEY,
  kind           TEXT    NOT NULL,
  certificate_id INTEGER NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  deployment_id  INTEGER REFERENCES deployments(id) ON DELETE CASCADE,
  attempt        INTEGER NOT NULL,
  trigger        TEXT    NOT NULL,
  status         TEXT    NOT NULL DEFAULT 'running',
  error          TEXT,
  started_at     TEXT    NOT NULL DEFAULT (datetime('now')),
  finished_at    TEXT
);
CREATE INDEX IF NOT EXISTS runs_cert ON runs(certificate_id, id DESC);

CREATE TABLE IF NOT EXISTS events (
  id      INTEGER PRIMARY KEY,
  run_id  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  seq     INTEGER NOT NULL,
  type    TEXT    NOT NULL,
  message TEXT    NOT NULL,
  detail  TEXT,
  level   TEXT    NOT NULL DEFAULT 'info',
  at      TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS events_run ON events(run_id, seq);

CREATE TABLE IF NOT EXISTS operation_logs (
  id            INTEGER PRIMARY KEY,
  action        TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   INTEGER,
  detail        TEXT,
  operator      TEXT NOT NULL DEFAULT 'admin',
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS operation_logs_recent ON operation_logs(id DESC);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
