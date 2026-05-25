//go:build integration

// Package tests holds Docker-based integration tests that exercise the exporter
// against a real Wazuh cluster. They are build-tagged `integration` and run only
// via `go test -tags=integration ./tests/...` (with the docker-compose stack up),
// never as part of the merge-gating unit run. See README.md.
//
// These assertions deliberately validate the cluster/per-node SHAPE against the
// live API (not just "an endpoint responds"), because the project's history shows
// unit mocks can drift from the real Wazuh response shape — that is the whole
// point of paying for a real-cluster stack here.
package tests

import (
	"io"
	"net/http"
	"os"
	"regexp"
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

// getReady polls /metrics until the named metric covers at least `want` distinct
// nodes — i.e. the worker has rejoined and the exporter has collected it. Returns
// the final body. This makes the cluster assertions robust to boot ordering.
func waitForNodes(t *testing.T, metric string, want int) string {
	t.Helper()
	var body string
	for i := 0; i < 60; i++ {
		body = get(t, "/metrics")
		if len(distinctNodes(body, metric)) >= want {
			return body
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s never covered %d nodes; last nodes=%v", metric, want, distinctNodes(body, metric))
	return body
}

// distinctNodes returns the set of node="..." label values on lines of metric.
func distinctNodes(body, metric string) []string {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metric) + `\{[^}]*node="([^"]+)"`)
	seen := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		seen[m[1]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

// TestExporterUpAndHealthy: liveness, readiness, and that /metrics serves wazuh_up.
func TestExporterUpAndHealthy(t *testing.T) {
	if body := get(t, "/health"); !strings.Contains(body, "ok") {
		t.Errorf("/health did not report ok: %s", body)
	}
	if body := get(t, "/ready"); !strings.Contains(body, "ready") {
		t.Errorf("/ready did not report ready: %s", body)
	}
	if body := get(t, "/metrics"); !strings.Contains(body, "wazuh_up") {
		t.Fatalf("/metrics missing wazuh_up (%d bytes)", len(body))
	}
}

// TestClusterDiscoveryAndPerNode: the exporter discovers both cluster nodes and
// collects manager-style metrics for EACH of them (master + worker), via the
// /cluster/<node>/* API. This is the regression guard for per-node collection.
func TestClusterDiscoveryAndPerNode(t *testing.T) {
	// Wait for the worker to rejoin and be collected (the stack may still be coming up).
	body := waitForNodes(t, "wazuh_manager_daemon_up", 2)

	if !strings.Contains(body, "wazuh_cluster_enabled") {
		t.Error("/metrics missing wazuh_cluster_enabled")
	}
	if nodes := distinctNodes(body, "wazuh_cluster_node_info"); len(nodes) < 2 {
		t.Errorf("cluster discovery should find >=2 nodes, got %v", nodes)
	}
	// Per-node metrics must cover both nodes, not just the master.
	for _, metric := range []string{
		"wazuh_manager_daemon_up",
		"wazuh_manager_info",
		"wazuh_analysisd_events_received_total",
		"wazuh_db_queries_received_total",
	} {
		if nodes := distinctNodes(body, metric); len(nodes) < 2 {
			t.Errorf("%s should cover >=2 nodes (per-node collection), got %v", metric, nodes)
		}
	}
	// config_valid is cluster-wide (one /cluster/configuration/validation call → per node).
	if nodes := distinctNodes(body, "wazuh_manager_config_valid"); len(nodes) < 2 {
		t.Errorf("config_valid should cover >=2 nodes, got %v", nodes)
	}
}

// TestAgentMetricsPopulated: the real agent enrolled and shows up in the fleet metrics.
func TestAgentMetricsPopulated(t *testing.T) {
	body := get(t, "/metrics")
	for _, want := range []string{"wazuh_agents{", "wazuh_agents_count"} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %s", want)
		}
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
