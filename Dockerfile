# syntax=docker/dockerfile:1

# ─── Stage 1: build the SPA ──────────────────────────────────────────
FROM --platform=$BUILDPLATFORM node:22-alpine AS spa
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ─── Stage 2: build the Go binary ────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=spa /src/web/dist ./web/dist
# CGO_ENABLED=0 is possible because the SQLite driver is pure Go
# (modernc.org/sqlite). That is what lets the runtime image be distroless
# rather than a glibc base carrying libssl.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /certcenter ./cmd/certcenter

# ─── Stage 3: minimal runtime ────────────────────────────────────────
# distroless/base rather than static: reaching Let's Encrypt and the DNS
# APIs needs the CA bundle, and certificate timestamps need tzdata.
FROM gcr.io/distroless/base-debian12:nonroot
COPY --from=build /certcenter /usr/local/bin/certcenter
WORKDIR /data
VOLUME /data
EXPOSE 3001
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/certcenter"]
CMD ["-config", "/data/config.toml"]
