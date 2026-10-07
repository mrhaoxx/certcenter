// Copyright 2026 The CertCenter Authors.
//
// SPDX-License-Identifier: Apache-2.0

// Command certcenter serves the CertCenter control plane: ACME certificate
// issuance and renewal over DNS-01, deployment to SSH hosts / webhooks /
// CDNs / the ServerAgent config center, and the embedded SPA.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mrhaoxx/certcenter/internal/bus"
	"github.com/mrhaoxx/certcenter/internal/config"
	"github.com/mrhaoxx/certcenter/internal/db"
	"github.com/mrhaoxx/certcenter/internal/deploy"
	"github.com/mrhaoxx/certcenter/internal/issuance"
	"github.com/mrhaoxx/certcenter/internal/scheduler"
	"github.com/mrhaoxx/certcenter/internal/server"
	"github.com/mrhaoxx/certcenter/web"
)

const (
	sessionTTL = 24 * time.Hour
	// configKey is what this service is registered as in the config center.
	configKey = "certcenter"
)

// app wires the pieces together and satisfies bus.API.
type app struct {
	store    db.Store
	issuer   *issuance.Issuer
	deployer *deploy.Deployer
}

func (a *app) Store() db.Store { return a.store }

func (a *app) Issue(ctx context.Context, certID int64, trigger string) error {
	return a.issuer.Issue(ctx, certID, trigger)
}

func (a *app) Deploy(ctx context.Context, certID int64, trigger string) error {
	return a.deployer.DeployCertificate(ctx, certID, trigger)
}

func main() {
	var (
		configPath  string
		listen      string
		externalURL string
		extraOrigin string
	)
	flag.StringVar(&configPath, "config", "config.toml", "path to the TOML config file")
	flag.StringVar(&listen, "listen", "", "override the configured listen address")
	flag.StringVar(&externalURL, "external-url", "",
		"external base URL of the UI (https enables Secure cookies and the Origin check)")
	flag.StringVar(&extraOrigin, "extra-origins", "",
		"comma-separated additional origins accepted for mutating requests")
	var healthcheck bool
	flag.BoolVar(&healthcheck, "healthcheck", false,
		"probe the configured address and exit 0 if healthy (for container health checks)")
	flag.Parse()

	// Positional argument keeps the Rust CLI's habit working:
	// certcenter /data/config.toml
	if healthcheck {
		// The runtime image is distroless: no shell, no curl. A container
		// health check therefore has to be the binary itself.
		os.Exit(probeHealth(configPath, listen))
	}
	if arg := flag.Arg(0); arg != "" {
		configPath = arg
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(configPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fatal(fmt.Errorf("load config: %w", err))
		}
		slog.Warn("config file not found, using defaults", "path", configPath)
		cfg = config.Default()
	}
	if listen != "" {
		host, port, perr := splitListen(listen)
		if perr != nil {
			fatal(perr)
		}
		cfg.Server.Host, cfg.Server.Port = host, port
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The config center is authoritative when configured, so its document
	// is merged in before anything is validated or opened.
	if cfg.Bus != nil && cfg.Bus.ManagementURL != nil {
		fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resolved, ferr := bus.FetchResolvedConfig(fetchCtx, *cfg.Bus.ManagementURL, configKey, cfg.Bus.ServiceID)
		cancel()
		if ferr != nil {
			// Not fatal: a config center that is down must not stop a
			// service whose local file is already valid.
			slog.Warn("could not fetch configuration from the config center", "err", ferr)
		} else if merr := cfg.MergeResolved(resolved); merr != nil {
			slog.Warn("the config center returned unusable configuration", "err", merr)
		} else {
			slog.Info("applied configuration from the config center")
		}
	}

	if err := cfg.Validate(); err != nil {
		fatal(fmt.Errorf("config validation failed: %w", err))
	}

	store, err := db.Open(cfg.Database.Path)
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	if err := server.SeedAdminPassword(ctx, store, cfg.Auth.PasswordHash); err != nil {
		fatal(err)
	}

	origin := originOf(externalURL)
	allowed := map[string]bool{}
	if origin != "" {
		allowed[origin] = true
	}
	for _, e := range splitNonEmpty(extraOrigin) {
		if o := originOf(e); o != "" {
			allowed[o] = true
		}
	}

	// The bus can replace the config at runtime, so everything reads it
	// through an atomic pointer rather than closing over one snapshot.
	live := &atomic.Pointer[config.Config]{}
	live.Store(cfg)
	liveConfig := live.Load

	broker := server.NewBroker()

	issuer := &issuance.Issuer{
		Store:     store,
		Registrar: &issuance.Registrar{},
		// Each timeline entry nudges the stream, so the page follows a run
		// as it happens rather than jumping at the end.
		OnProgress: func() { broker.Publish(server.TopicRuns) },
		// Read per issuance, not captured here: a config push that changes
		// dns_verification must take effect without a restart, the same way
		// the deployer's management URL does below.
		DoH: func() issuance.DoHSettings {
			c := liveConfig()
			fallback := db.DNSSettings{
				Server: c.DoHServer(), Retries: c.DNSMaxRetries(), Skip: c.DNSVerification.Skip,
				SkipWaitSeconds: db.DefaultSkipWaitSeconds,
			}
			// The settings table wins; config.toml only supplies the value
			// before anything has been saved from the UI. Same arrangement
			// as the admin password.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			v, err := store.GetDNSSettings(ctx, fallback)
			if err != nil {
				slog.Warn("could not read DNS settings; using the configured values", "err", err)
				v = fallback
			}
			return issuance.DoHSettings{
				Server: v.Server, Retries: v.Retries, Interval: 5 * time.Second, Skip: v.Skip,
				SkipWait: time.Duration(v.SkipWaitSeconds) * time.Second,
			}
		},
	}
	deployer := &deploy.Deployer{
		Store: store,
		ManagementURL: func() string {
			c := liveConfig()
			if c.Bus != nil && c.Bus.ManagementURL != nil {
				return *c.Bus.ManagementURL
			}
			return ""
		},
	}
	srv := &server.Server{
		DB:             store,
		Sessions:       server.NewSessionManager([]byte(cfg.Auth.SessionKey), sessionTTL),
		Config:         liveConfig,
		AllowedOrigins: allowed,
		SecureCookies:  strings.HasPrefix(origin, "https://"),
		ConfigPath:     configPath,
		Running:        server.NewRunning(),
		Issuer:         issuer,
		Deployer:       deployer,
		Events:         broker,
	}

	sched := &scheduler.Scheduler{
		Store:    store,
		Issuer:   issuer,
		Deployer: deployer,
		OnChange: func() {
			broker.Publish(server.TopicCertificates)
			broker.Publish(server.TopicRuns)
		},
	}
	go sched.Run(ctx)

	if cfg.Bus != nil && cfg.Bus.URL != "" {
		application := &app{store: store, issuer: issuer, deployer: deployer}
		handler := &bus.Handler{App: application}
		client := &bus.Client{
			Config:   cfg.Bus,
			Dispatch: handler.Dispatch,
			FetchConfig: func(ctx context.Context) (string, error) {
				c := liveConfig()
				if c.Bus == nil || c.Bus.ManagementURL == nil {
					return "", fmt.Errorf("management_url is not configured")
				}
				return bus.FetchResolvedConfig(ctx, *c.Bus.ManagementURL, configKey, c.Bus.ServiceID)
			},
			ApplyConfig: func(resolved string) error {
				// Merge onto a copy and validate before publishing, so a bad
				// push leaves the running configuration untouched.
				next := liveConfig().Clone()
				if err := next.MergeResolved(resolved); err != nil {
					return err
				}
				if err := next.Validate(); err != nil {
					return fmt.Errorf("pushed configuration is invalid: %w", err)
				}
				live.Store(next)
				slog.Info("applied a configuration push")
				return nil
			},
		}
		go client.Run(ctx)
	}

	// No ReadTimeout/WriteTimeout: they would cut off the SSE stream. Header
	// and idle timeouts bound slow-header and idle socket abuse; body size
	// is capped in the handler chain.
	httpSrv := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	// Runs left open by a previous process would otherwise stay "running"
	// forever, with their certificates stuck in "pending" — a state the
	// renewal sweep skips, so nothing would ever retry them.
	if n, err := store.ReapOrphanedRuns(context.Background()); err != nil {
		slog.Warn("could not reconcile interrupted runs", "err", err)
	} else if n > 0 {
		slog.Warn("closed runs interrupted by a restart; the certificates can be retried", "runs", n)
	}

	if web.IsPlaceholder() {
		// Not fatal: `go build ./...` and the tests have to work without
		// Node. But a binary shipped like this serves a blank page, so say
		// so here rather than letting a browser be the one to report it.
		slog.Warn("the embedded web UI is the placeholder, not a real build; " +
			"run hack/build-webui.sh before compiling or the interface will be blank")
	}
	slog.Info("certcenter listening", "addr", cfg.Addr(), "database", cfg.Database.Path)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
	slog.Info("shutting down")
}

// originOf reduces a URL to its scheme://host origin for the CSRF check.
func originOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func splitListen(addr string) (string, int, error) {
	host, portStr, ok := strings.Cut(addr, ":")
	if !ok {
		return "", 0, fmt.Errorf("--listen must be host:port, got %q", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("--listen has an invalid port: %q", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return host, port, nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(err error) {
	slog.Error("fatal", "err", err)
	os.Exit(1)
}

// probeHealth requests /healthz from the address this process would serve
// on, and reports a process exit code.
func probeHealth(configPath, listenOverride string) int {
	addr := listenOverride
	if addr == "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			return 1
		}
		addr = cfg.Addr()
	}
	// 0.0.0.0 is where the server listens, not somewhere to connect to.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: HTTP %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
