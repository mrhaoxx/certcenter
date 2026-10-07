#!/usr/bin/env bash
# Build the SPA into web/dist, which web/embed.go embeds. Requires Node >= 20.
# CI and the Dockerfile run this; the committed web/dist/index.html is only a
# placeholder so `go build ./...` works without Node installed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/web"
npm ci
npm run build
