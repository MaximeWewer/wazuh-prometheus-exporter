package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/exporter"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

func testMux() http.Handler {
	self := monitoring.New("1.2.3-test", time.Now())
	// Orchestrator with no domain collectors emits wazuh_up=0 (nothing collected)
	// but is ready (self-metrics-only mode).
	exp := exporter.New(logger.New("error"), self, time.Second, "manager")
	mainReg := prometheus.NewRegistry()
	mainReg.MustRegister(exp)
	return newMux(mainReg, self.Registry(), "1.2.3-test", time.Now().Add(-5*time.Second), exp.Ready)
}

func TestHealthEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %v, want ok", body["status"])
	}
	if body["version"] != "1.2.3-test" {
		t.Errorf("version = %v", body["version"])
	}
	if _, ok := body["uptime_seconds"]; !ok {
		t.Error("uptime_seconds missing")
	}
}

func TestReadyEndpoint_Ready(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (self-metrics-only is ready)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"ready"`) {
		t.Errorf("body = %q, want status ready", rec.Body.String())
	}
}

func TestReadyEndpoint_NotReady(t *testing.T) {
	reg := prometheus.NewRegistry()
	mux := newMux(reg, reg, "v", time.Now(), func() bool { return false })
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when not ready", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not ready") {
		t.Errorf("body = %q, want status not ready", rec.Body.String())
	}
}

func TestLandingEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	b := rec.Body.String()
	if !strings.Contains(b, "/metrics") || !strings.Contains(b, "/health") {
		t.Error("landing page should link to /metrics and /health")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "wazuh_up") {
		t.Error("/metrics should expose wazuh_up")
	}
}

func TestInternalMetricsEndpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	b := rec.Body.String()
	if !strings.Contains(b, "wazuh_exporter_build_info") {
		t.Error("/internal/metrics should expose wazuh_exporter_build_info")
	}
	if !strings.Contains(b, "go_goroutines") {
		t.Error("/internal/metrics should expose Go runtime metrics")
	}
}

func TestRegistriesAreIsolated(t *testing.T) {
	mux := testMux()

	mrec := httptest.NewRecorder()
	mux.ServeHTTP(mrec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if mb := mrec.Body.String(); strings.Contains(mb, "go_goroutines") || strings.Contains(mb, "wazuh_exporter_build_info") {
		t.Error("/metrics must not expose self-metrics (registry leak)")
	}

	irec := httptest.NewRecorder()
	mux.ServeHTTP(irec, httptest.NewRequest(http.MethodGet, "/internal/metrics", nil))
	if strings.Contains(irec.Body.String(), "wazuh_up") {
		t.Error("/internal/metrics must not expose wazuh_up (registry leak)")
	}
}

func TestUnknownPathReturns404(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestMuxSetsSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	testMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers not applied to mux responses")
	}
}
