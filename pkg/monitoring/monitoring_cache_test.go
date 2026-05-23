package monitoring

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSelfMetrics_CacheAndBreakerState(t *testing.T) {
	m := New("test", time.Now())
	m.CacheHits.Inc()
	m.CacheMisses.Add(2)
	m.RegisterCircuitBreakerState(func() float64 { return 2 }) // open

	expected := `
# HELP wazuh_exporter_cache_hits_total Total Wazuh API response cache hits.
# TYPE wazuh_exporter_cache_hits_total counter
wazuh_exporter_cache_hits_total 1
# HELP wazuh_exporter_cache_misses_total Total Wazuh API response cache misses.
# TYPE wazuh_exporter_cache_misses_total counter
wazuh_exporter_cache_misses_total 2
# HELP wazuh_exporter_circuit_breaker_state Wazuh API circuit breaker state (0 closed, 1 half-open, 2 open).
# TYPE wazuh_exporter_circuit_breaker_state gauge
wazuh_exporter_circuit_breaker_state 2
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(expected),
		"wazuh_exporter_cache_hits_total", "wazuh_exporter_cache_misses_total", "wazuh_exporter_circuit_breaker_state"); err != nil {
		t.Error(err)
	}
}
