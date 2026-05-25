package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/security"
)

// newMux builds the exporter's HTTP handler: /metrics (domain registry),
// /internal/metrics (exporter self-metrics), /health (liveness JSON), /ready
// (readiness — 200 once a collection has succeeded, else 503), and / (HTML info
// page), wrapped with security headers. ready reports collection readiness.
func newMux(mainReg, selfReg *prometheus.Registry, version string, started time.Time, ready func() bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(mainReg, promhttp.HandlerOpts{}))
	mux.Handle("/internal/metrics", promhttp.HandlerFor(selfReg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", healthHandler(version, started))
	mux.HandleFunc("/ready", readyHandler(ready))
	mux.HandleFunc("/", landingHandler(version))
	return security.SecurityHeaders(mux)
}

// healthHandler is liveness: 200 as soon as the HTTP server is up. It does NOT
// reflect Wazuh reachability — that is the wazuh_up metric's job.
func healthHandler(version string, started time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		uptime := int64(time.Since(started).Seconds())
		if uptime < 0 {
			uptime = 0
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"version":        version,
			"uptime_seconds": uptime,
		})
	}
}

// readyHandler is readiness: 200 once a collection has succeeded at least once
// (or in self-metrics-only mode), else 503. Readiness is sticky, so a later
// transient Wazuh outage does NOT flip it back — that would deregister the
// exporter from its Service and suppress the wazuh_up=0 signal.
func readyHandler(ready func() bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		status, code := "ready", http.StatusOK
		if !ready() {
			status, code = "not ready", http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status})
	}
}

func landingHandler(version string) http.HandlerFunc {
	page := fmt.Sprintf("<!DOCTYPE html><html><head><title>Wazuh Prometheus Exporter</title></head>"+
		"<body><h1>Wazuh Prometheus Exporter</h1><p>Version: %s</p>"+
		`<ul><li><a href="/metrics">/metrics</a></li><li><a href="/health">/health</a></li><li><a href="/ready">/ready</a></li></ul>`+
		"</body></html>", html.EscapeString(version))
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}
