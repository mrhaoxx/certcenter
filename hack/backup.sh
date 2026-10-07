#!/usr/bin/env bash
# Copyright 2026 The CertCenter Authors.
#
# SPDX-License-Identifier: Apache-2.0
#
# Snapshot the CertCenter database and config, encrypted to the backup key.
#
# Everything secret the service holds lives in one SQLite file: ACME account
# private keys, DNS and deploy-target credentials, certificate private keys,
# and the admin password hash. config.toml carries the session key.
#
# The snapshot is taken with VACUUM INTO, not cp. The database runs in WAL
# mode, so copying the file while a write is in flight yields a torn image
# that only reveals itself at restore time. VACUUM INTO goes through
# SQLite's own machinery and writes a consistent, compacted database.
#
# Encryption is to a public key whose private half never touches this
# machine. A passphrase would have to be readable by cron, and therefore by
# anyone who takes the host — which is precisely the situation a backup
# exists for.
set -euo pipefail

readonly ROOT="${CERTCENTER_ROOT:-$HOME/certcenter-go}"
readonly DB="$ROOT/data/certcenter.db"
readonly CONFIG="$ROOT/data/config.toml"
readonly DEST="$ROOT/backups"
readonly GNUPG="$HOME/.certcenter-gpg"
readonly RECIPIENT="6BB842633A4C255D943C7476F0AE0308A8EC51E5"
readonly KEEP_DAYS=14

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

[ -f "$DB" ] || { log "FATAL no database at $DB"; exit 1; }
mkdir -p "$DEST"; chmod 700 "$DEST"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# sudo: the container runs as uid 65532 and owns the data files.
sudo sqlite3 "$DB" "VACUUM INTO '$work/certcenter.db'"
sudo chown "$(id -u):$(id -g)" "$work/certcenter.db"
[ -f "$CONFIG" ] && { sudo cp "$CONFIG" "$work/config.toml"; sudo chown "$(id -u):$(id -g)" "$work/config.toml"; }

# Verify the snapshot before trusting it: a backup nobody checks is a
# guess. integrity_check walks every page and index.
integrity=$(sqlite3 "$work/certcenter.db" "PRAGMA integrity_check;")
[ "$integrity" = "ok" ] || { log "FATAL snapshot failed integrity_check: $integrity"; exit 1; }
accounts=$(sqlite3 "$work/certcenter.db" "SELECT count(*) FROM acme_accounts;")

out="$DEST/certcenter-$stamp.tar.gz.gpg"
tar -C "$work" -czf - .   | gpg --homedir "$GNUPG" --batch --yes --trust-model always         --encrypt --recipient "$RECIPIENT" --output "$out"
chmod 600 "$out"

log "wrote $out ($(stat -c%s "$out") bytes, $accounts ACME account(s))"

# Rotate. -mtime +N deletes strictly older than N days.
deleted=$(find "$DEST" -name 'certcenter-*.tar.gz.gpg' -type f -mtime +$KEEP_DAYS -print -delete | wc -l)
[ "$deleted" -gt 0 ] && log "pruned $deleted backup(s) older than $KEEP_DAYS days"
exit 0
