package main

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guardx/gateway/internal/bundle"
	"github.com/guardx/gateway/internal/config"
	"github.com/guardx/gateway/internal/detector"
	"github.com/guardx/gateway/internal/evidence"
	"github.com/guardx/gateway/internal/gwmetrics"
	"github.com/guardx/gateway/internal/httpapi"
	"github.com/guardx/gateway/internal/metrics"
	"github.com/guardx/gateway/internal/policy"
	"github.com/guardx/gateway/internal/proxy"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Trust store — either pinned via env or bootstrapped from Control API.
	trust, err := buildTrust(ctx, cfg, logger)
	if err != nil {
		logger.Error("trust store", "err", err)
		os.Exit(1)
	}

	snap := policy.NewSnapshot()
	metricsReg := metrics.NewRegistry()
	metricsCollector := &gwmetrics.Collector{
		Reg: metricsReg, Tenant: cfg.Tenant, Env: cfg.Environment,
	}

	// Evidence emitter: HTTP to Control API if configured, else stdout.
	// The spool file survives Control API outages (spec §4.4).
	var emitter evidence.Emitter
	evidenceURL := os.Getenv("GUARDX_EVIDENCE_BASE_URL")
	if evidenceURL == "" {
		evidenceURL = cfg.ControlBaseURL // default: same host as bundle pull
	}
	spool := os.Getenv("GUARDX_EVIDENCE_SPOOL")
	if spool == "" {
		spool = "/tmp/guardx-evidence.spool.jsonl"
	}
	if os.Getenv("GUARDX_EVIDENCE_DISABLE_HTTP") == "1" {
		emitter = &evidence.StdoutEmitter{Log: logger}
	} else {
		he := evidence.NewHTTPEmitter(evidenceURL, cfg.ControlAPIKey, spool, logger)
		if err := he.Start(); err != nil {
			logger.Error("evidence emitter start", "err", err)
			os.Exit(1)
		}
		defer he.Close()
		emitter = he
	}

	// Detector registry + backends.
	registry := detector.NewRegistry()
	secretsBackend, err := detector.NewSecretsBackend()
	if err != nil {
		logger.Error("secrets backend", "err", err)
		os.Exit(1)
	}
	registry.Register(secretsBackend)
	// PII backend (HTTP) — its URL comes from env.
	piiURL := os.Getenv("GUARDX_PII_BACKEND_URL")
	if piiURL == "" {
		piiURL = "http://pii:9100"
	}
	registry.Register(detector.NewHTTPBackend(detector.HTTPBackendConfig{
		Name:     "presidio-ensemble@1.4.0",
		Scenario: "pii",
		BaseURL:  piiURL,
		Timeout:  400 * time.Millisecond,
	}))
	if safetyURL := os.Getenv("GUARDX_SAFETY_BACKEND_URL"); safetyURL != "" {
		registry.Register(detector.NewHTTPBackend(detector.HTTPBackendConfig{
			Name:     "safety-ensemble@1.2.0",
			Scenario: "content_safety",
			BaseURL:  safetyURL,
			Timeout:  1500 * time.Millisecond,
		}))
	}
	if nliURL := os.Getenv("GUARDX_NLI_BACKEND_URL"); nliURL != "" {
		registry.Register(detector.NewHTTPBackend(detector.HTTPBackendConfig{
			Name:     "nli-groundedness@2.1.0",
			Scenario: "hallucination",
			BaseURL:  nliURL,
			Timeout:  2000 * time.Millisecond,
		}))
	}
	dispatcher := detector.NewDispatcher(registry)

	client := bundle.NewClient(
		cfg.ControlBaseURL, cfg.ControlAPIKey,
		cfg.Tenant, cfg.Environment, trust,
		cfg.PollInterval, logger,
	)
	go client.Run(ctx)
	go func() {
		for m := range client.Updates() {
			idx, err := policy.Build(m)
			if err != nil {
				logger.Error("policy index build", "err", err)
				continue
			}
			snap.Store(idx)
			metricsCollector.ObserveBundleInstalled(m.BundleSeq, len(m.Policies), m.CreatedAt)
			logger.Info("bundle installed",
				"seq", m.BundleSeq, "policies", len(m.Policies), "tenant", m.Tenant)
		}
	}()

	// Bundle-age gauge — updated per poll tick so the alerting stack can
	// warn when the last-installed bundle passes max_age_hours (spec §3.2).
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if idx := snap.Load(); idx != nil {
					metricsCollector.UpdateBundleAge(idx.CreatedAt)
				}
			}
		}
	}()

	upstream, err := url.Parse(cfg.UpstreamBaseURL)
	if err != nil {
		logger.Error("upstream url", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if snap.Load() == nil {
			http.Error(w, "no bundle", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.Handle("/metrics", metricsReg.Handler())
	mux.Handle("/v1/guard/check", &httpapi.CheckHandler{
		Snap: snap, Emitter: emitter, Dispatcher: dispatcher, Metrics: metricsCollector,
		Tenant: cfg.Tenant, Environment: cfg.Environment,
	})
	proxyHandler := proxy.New(snap, emitter, dispatcher, upstream, cfg.Tenant, cfg.Environment)
	proxyHandler.Metrics = metricsCollector
	mux.Handle("/v1/proxy/", proxyHandler)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Graceful shutdown.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		logger.Info("shutting down")
		shutdownCtx, c2 := context.WithTimeout(context.Background(), 10*time.Second)
		defer c2()
		_ = srv.Shutdown(shutdownCtx)
		cancel()
	}()

	logger.Info("gateway listening",
		"addr", cfg.Addr,
		"tenant", cfg.Tenant, "env", cfg.Environment,
		"upstream", cfg.UpstreamBaseURL,
	)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("http server", "err", err)
		os.Exit(1)
	}
}

func buildTrust(ctx context.Context, cfg *config.Config, logger *slog.Logger) (bundle.TrustStore, error) {
	keys := map[string]ed25519.PublicKey{}
	if cfg.SigningPublicKey != nil {
		keys[cfg.SigningKeyID] = cfg.SigningPublicKey
	} else {
		// Bootstrap from Control API (dev convenience).
		logger.Info("bootstrapping signing key from control API",
			"base", cfg.ControlBaseURL, "env", cfg.Environment)
		bctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		var (
			keyID string
			pub   ed25519.PublicKey
			err   error
		)
		// Retry a few times because the control API may not be up yet on cold-start.
		for i := 0; i < 30; i++ {
			keyID, pub, err = bundle.BootstrapKey(bctx, cfg.ControlBaseURL, cfg.ControlAPIKey, cfg.Environment)
			if err == nil {
				break
			}
			logger.Warn("bootstrap key: retry", "attempt", i+1, "err", err)
			time.Sleep(2 * time.Second)
		}
		if err != nil {
			return nil, err
		}
		keys[keyID] = pub
	}
	return &bundle.StaticTrustStore{Keys: keys}, nil
}
