//go:build integration

// Package tests holds Docker-based integration tests that exercise the exporter
// against a real Wazuh manager. They are build-tagged `integration` and run only
// via `go test -tags=integration ./tests/...` (with the docker-compose stack up),
// never as part of the merge-gating unit run. See README.md.
package tests

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func exporterAddr() string {
	if a := os.Getenv("EXPORTER_ADDR"); a != "" {
		return a
	}
	return "http://localhost:9555"
}

// get fetches path from the exporter, retrying while the stack comes up.
func get(t *testing.T, path string) string {
	t.Helper()
	var lastErr error
	for i := 0; i < 60; i++ {
		resp, err := http.Get(exporterAddr() + path)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return string(body)
		}
		lastErr = nil
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("GET %s never succeeded: %v", path, lastErr)
	return ""
}

// TestExporterUpAndHealthy checks the exporter scrapes a live Wazuh manager: the
// /metrics endpoint serves and reports wazuh_up.
func TestExporterUpAndHealthy(t *testing.T) {
	if body := get(t, "/health"); !strings.Contains(body, "ok") {
		t.Errorf("/health did not report ok: %s", body)
	}
	body := get(t, "/metrics")
	if !strings.Contains(body, "wazuh_up") {
		t.Fatalf("/metrics missing wazuh_up (%d bytes)", len(body))
	}
}

// TestSelfMetricsExposed checks the internal self-metrics endpoint.
func TestSelfMetricsExposed(t *testing.T) {
	body := get(t, "/internal/metrics")
	for _, want := range []string{"wazuh_exporter_build_info", "wazuh_exporter_scrape_duration_seconds"} {
		if !strings.Contains(body, want) {
			t.Errorf("/internal/metrics missing %s", want)
		}
	}
}
