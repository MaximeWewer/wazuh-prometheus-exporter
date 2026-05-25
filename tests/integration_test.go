//go:build integration

// Package tests holds Docker-based integration tests that exercise the exporter
// against a real Wazuh manager — either the cluster stack (docker-compose.cluster.yml)
// or the standalone stack (docker-compose.standalone.yml); the per-node test is
// mode-aware. They are build-tagged `integration` and run only via
// `go test -tags=integration ./tests/...` (with a stack up), never in the
// merge-gating unit run.
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

// waitForMetric polls /metrics until the named metric appears (the exporter has
// collected at least once), returning the final body. Tolerates a slow boot.
func waitForMetric(t *testing.T, metric string) string {
	t.Helper()
	var body string
	for i := 0; i < 60; i++ {
		body = get(t, "/metrics")
		if strings.Contains(body, metric) {
			return body
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s never appeared in /metrics (exporter not collecting?)", metric)
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

// clusterEnabled reads wazuh_cluster_enabled from a /metrics body: (enabled, found).
func clusterEnabled(body string) (enabled, found bool) {
	m := regexp.MustCompile(`(?m)^wazuh_cluster_enabled\{[^}]*\}\s+(\d)`).FindStringSubmatch(body)
	if m == nil {
		return false, false
	}
	return m[1] == "1", true
}

// TestPerNodeCollection is the per-node collection regression guard, mode-aware so
// it passes against EITHER stack: the cluster stack (>=2 nodes discovered via
// /cluster/healthcheck, each collected through /cluster/<node>/*) or the
// standalone stack (1 node via /manager/*, cluster_enabled=0, no node_info).
func TestPerNodeCollection(t *testing.T) {
	body := waitForMetric(t, "wazuh_cluster_enabled") // wait until collection is ready
	enabled, _ := clusterEnabled(body)

	want := 1
	if enabled {
		want = 2
		// Wait for the worker to rejoin and be collected (the stack may still boot).
		body = waitForNodes(t, "wazuh_manager_daemon_up", 2)
		if nodes := distinctNodes(body, "wazuh_cluster_node_info"); len(nodes) < 2 {
			t.Errorf("cluster discovery should find >=2 nodes, got %v", nodes)
		}
	} else if n := len(distinctNodes(body, "wazuh_cluster_node_info")); n != 0 {
		t.Errorf("standalone must not emit cluster_node_info, got %d node(s)", n)
	}

	// Per-node metrics must cover every node (2 in cluster, 1 in standalone).
	for _, metric := range []string{
		"wazuh_manager_daemon_up",
		"wazuh_manager_info",
		"wazuh_analysisd_events_received_total",
		"wazuh_db_queries_received_total",
		"wazuh_manager_config_valid",
	} {
		if nodes := distinctNodes(body, metric); len(nodes) < want {
			t.Errorf("%s should cover >=%d node(s), got %v", metric, want, nodes)
		}
	}
}

// TestAgentMetricsPopulated: the real agent enrolled and shows up in the fleet metrics.
func TestAgentMetricsPopulated(t *testing.T) {
	body := waitForMetric(t, "wazuh_agents_count") // agent enrollment + first scrape may lag
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
