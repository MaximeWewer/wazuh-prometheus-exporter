// Command wazuh-exporter is a Prometheus exporter for Wazuh.
//
// It loads configuration from the environment, then serves /metrics, /health
// and an info page over an exporter-toolkit HTTP server (optional TLS and
// basic-auth via a web-config file), shutting down gracefully on SIGTERM/SIGINT.
// newServer wires the domain collectors (local .state files plus, when API
// credentials are configured, the cache→breaker→client Wazuh API chain) and the
// self/up metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/cache"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/circuitbreaker"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/config"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/exporter"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

// Version is the exporter version, injected at build time via
// -ldflags "-X main.Version=...". It defaults to "dev" for local builds.
var Version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run holds the program logic so it can be exercised by tests. It returns the
// process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("wazuh-exporter", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		// An explicit help request (-h/--help) is not an error: exit 0.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}

	cfg, err := config.Load()
	if err != nil {
		boot := logger.New("info")
		boot.Error().Err(err).Msg("configuration error")
		return 1
	}
	defer cfg.Clear()

	log := logger.New(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	return serve(ctx, newServer(cfg, log), cfg, log)
}

// newServer builds the exporter HTTP server with the configured timeouts. Addr
// is informational only — exporter-toolkit binds via FlagConfig.WebListenAddresses.
func newServer(cfg *config.Config, log zerolog.Logger) *http.Server {
	started := time.Now()

	self := monitoring.New(Version, started)

	// All domain metrics come from the Wazuh API (the deprecated local .state
	// files are no longer read). Collection is therefore opt-in on credentials:
	// with none configured, only self-metrics are served.
	var collectors []exporter.Collector
	if cfg.APIUsername != "" && !cfg.APIPassword.Empty() {
		collectors = append(collectors, newAPIChain(cfg, self, log)...)
	} else {
		log.Warn().Msg("domain collectors disabled: no API credentials")
	}

	// Pre-initialize each collector's self-metric series so they export 0 before
	// the first success/failure (so absence-based alerts behave).
	for _, c := range collectors {
		self.CollectorSuccess.WithLabelValues(c.Name())
		self.CollectorErrors.WithLabelValues(c.Name(), "collect")
		self.CollectorErrors.WithLabelValues(c.Name(), "panic")
	}

	exp := exporter.New(log, self, cfg.ScrapeTimeout, cfg.NodeName, collectors...)

	mainReg := prometheus.NewRegistry()
	mainReg.MustRegister(exp)

	return &http.Server{
		Addr:         cfg.ListenAddress,
		Handler:      newMux(mainReg, self.Registry(), Version, started),
		ReadTimeout:  cfg.ServerReadTimeout,
		WriteTimeout: cfg.ServerWriteTimeout,
		IdleTimeout:  cfg.ServerIdleTimeout,
	}
}

// newAPIChain builds the Wazuh API client wrapped by the circuit breaker and
// response cache (cache→breaker→client), wires the cache/breaker self-metrics,
// and returns the API collectors built on that single shared chain. It returns
// nil (logging the error) if the client cannot be built, so a bad API config
// never aborts startup.
func newAPIChain(cfg *config.Config, self *monitoring.Metrics, log zerolog.Logger) []exporter.Collector {
	client, err := api.NewClient(api.Options{
		BaseURL:    cfg.APIURL,
		Username:   cfg.APIUsername,
		Password:   cfg.APIPassword,
		CAFile:     cfg.APICAFile,
		CertFile:   cfg.APICertFile,
		KeyFile:    cfg.APIKeyFile,
		SkipVerify: cfg.APITLSSkipVerify,
		Timeout:    cfg.ScrapeTimeout,
		Logger:     log,
	})
	if err != nil {
		log.Error().Err(err).Msg("Wazuh API client init failed; API collectors disabled")
		return nil
	}
	breaker := circuitbreaker.New(client, circuitbreaker.WithLogger(log))
	cached := cache.New(breaker, cfg.CacheTTL, cache.WithHooks(self.CacheHits.Inc, self.CacheMisses.Inc))
	self.RegisterCircuitBreakerState(func() float64 { return float64(breaker.State()) })
	return []exporter.Collector{
		exporter.NewAgentsCollector(cached, cfg.NodeName, log),
		exporter.NewClusterCollector(cached, cfg.NodeName, log),
	}
}

// serve runs the exporter-toolkit HTTP server until ctx is cancelled (a
// SIGTERM/SIGINT signal) or the server fails, then shuts down gracefully.
func serve(ctx context.Context, srv *http.Server, cfg *config.Config, log zerolog.Logger) int {
	systemdSocket := false
	flags := &web.FlagConfig{
		WebListenAddresses: &[]string{cfg.ListenAddress},
		WebSystemdSocket:   &systemdSocket,
		WebConfigFile:      &cfg.WebConfigFile,
	}

	log.Info().Str("version", Version).Str("listen_address", cfg.ListenAddress).Msg("starting HTTP server")

	errCh := make(chan error, 1)
	go func() {
		errCh <- web.ListenAndServe(srv, flags, newToolkitLogger(cfg.LogLevel))
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("HTTP server error")
			return 1
		}
		return 0
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received; draining in-flight requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ServerShutdownTimeout)
		defer cancel()
		shutdownErr := srv.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			log.Error().Err(shutdownErr).Msg("graceful shutdown timed out; forcing close")
			_ = srv.Close()
		}
		// Shutdown/Close make ListenAndServe return; drain errCh so we never leak
		// the serve goroutine and so a bind/serve error is not silently swallowed.
		if serveErr := <-errCh; serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Error().Err(serveErr).Msg("HTTP server error during shutdown")
			return 1
		}
		if shutdownErr != nil {
			return 1
		}
		log.Info().Msg("shutdown complete")
		return 0
	}
}

// newToolkitLogger builds the stdlib *slog.Logger that prometheus/exporter-toolkit
// requires for its internal logging, mapped from the configured log level.
func newToolkitLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
