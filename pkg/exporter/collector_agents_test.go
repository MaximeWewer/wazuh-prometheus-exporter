package exporter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

type fakeAPIClient struct {
	body []byte
	err  error
}

func (f fakeAPIClient) Get(_ context.Context, _ string) ([]byte, error) { return f.body, f.err }

func newAgentsExporter(client fakeAPIClient) (*Exporter, *monitoring.Metrics) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, NewAgentsCollector(client, logger.New("error")))
	return e, mon
}

// pathAPIClient returns a different body per request path (for the overview call).
type pathAPIClient struct{ bodies map[string][]byte }

func (p pathAPIClient) Get(_ context.Context, path string) ([]byte, error) {
	if b, ok := p.bodies[path]; ok {
		return b, nil
	}
	return []byte(`{"data":{}}`), nil
}

func TestAgentsCollector_OverviewGroupsVersionsLastRegistered(t *testing.T) {
	client := pathAPIClient{bodies: map[string][]byte{
		"/agents/summary/status": []byte(`{"data":{"connection":{"active":3,"total":3}}}`),
		"/overview/agents": []byte(`{"data":{
			"groups":[{"name":"default","count":2},{"name":"web","count":1}],
			"agent_version":[{"version":"Wazuh v4.14.0","count":3}],
			"last_registered_agent":[{"id":"003","name":"web01","version":"Wazuh v4.14.0","status":"active"}]}}`),
	}}
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, NewAgentsCollector(client, logger.New("error")))

	expGroup := `
# HELP wazuh_agents_group Number of Wazuh agents by group.
# TYPE wazuh_agents_group gauge
wazuh_agents_group{group="default",node="manager"} 2
wazuh_agents_group{group="web",node="manager"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expGroup), "wazuh_agents_group"); err != nil {
		t.Errorf("wazuh_agents_group: %v", err)
	}
	if n := testutil.CollectAndCount(e, "wazuh_agents_version"); n != 1 {
		t.Errorf("agents_version → 1 series, got %d", n)
	}
	if n := testutil.CollectAndCount(e, "wazuh_last_registered_agent_info"); n != 1 {
		t.Errorf("last_registered_agent_info → 1 series, got %d", n)
	}
}

func TestAgentsCollector_OSAndOutdated(t *testing.T) {
	client := pathAPIClient{bodies: map[string][]byte{
		"/agents/summary/status": []byte(`{"data":{"connection":{"active":3,"total":3}}}`),
		"/overview/agents": []byte(`{"data":{
			"agent_os":[{"os":{"name":"Ubuntu 22.04","platform":"ubuntu"},"count":2},{"os":{"platform":"windows"},"count":1}]}}`),
		"/agents/outdated": []byte(`{"data":{"total_affected_items":4}}`),
	}}
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, NewAgentsCollector(client, logger.New("error")))

	expOS := `
# HELP wazuh_agents_os Number of Wazuh agents by operating system.
# TYPE wazuh_agents_os gauge
wazuh_agents_os{node="manager",os="Ubuntu 22.04"} 2
wazuh_agents_os{node="manager",os="windows"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expOS), "wazuh_agents_os"); err != nil {
		t.Errorf("agents_os (name, platform fallback): %v", err)
	}
	expOutdated := `
# HELP wazuh_agents_outdated Number of Wazuh agents running an outdated version.
# TYPE wazuh_agents_outdated gauge
wazuh_agents_outdated{node="manager"} 4
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expOutdated), "wazuh_agents_outdated"); err != nil {
		t.Errorf("agents_outdated: %v", err)
	}
}

func TestAgentsCollector_OverviewFailureKeepsStatusMetrics(t *testing.T) {
	// /overview/agents missing/erroring must not drop the status metrics.
	client := pathAPIClient{bodies: map[string][]byte{
		"/agents/summary/status": []byte(`{"data":{"connection":{"active":5,"total":5}}}`),
		"/overview/agents":       []byte(`{"error":403,"message":"denied","data":{}}`),
	}}
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, NewAgentsCollector(client, logger.New("error")))
	if n := testutil.CollectAndCount(e, "wazuh_agents"); n != 1 {
		t.Errorf("status still emitted despite overview error, got %d", n)
	}
	if n := testutil.CollectAndCount(e, "wazuh_agents_group"); n != 0 {
		t.Errorf("overview error → no group series, got %d", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("agents", "collect")); got != 0 {
		t.Errorf("overview is best-effort → collector not errored, got %v", got)
	}
}

func TestAgentsCollector_EmitsConnectionAndTotal(t *testing.T) {
	body := `{"data":{"connection":{"active":10,"disconnected":2,"never_connected":1,"pending":0,"total":13},
	          "configuration":{"synced":11,"not_synced":2}}}`
	e, _ := newAgentsExporter(fakeAPIClient{body: []byte(body)})

	expActive := `
# HELP wazuh_agents Number of Wazuh agents by connection status.
# TYPE wazuh_agents gauge
wazuh_agents{node="manager",status="active"} 10
wazuh_agents{node="manager",status="disconnected"} 2
wazuh_agents{node="manager",status="never_connected"} 1
wazuh_agents{node="manager",status="pending"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expActive), "wazuh_agents"); err != nil {
		t.Errorf("wazuh_agents: %v", err)
	}
	expCount := `
# HELP wazuh_agents_count Total number of Wazuh agents.
# TYPE wazuh_agents_count gauge
wazuh_agents_count{node="manager"} 13
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expCount), "wazuh_agents_count"); err != nil {
		t.Errorf("wazuh_agents_count: %v", err)
	}
	expConfig := `
# HELP wazuh_agents_config Number of Wazuh agents by configuration sync state.
# TYPE wazuh_agents_config gauge
wazuh_agents_config{node="manager",state="not_synced"} 2
wazuh_agents_config{node="manager",state="synced"} 11
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expConfig), "wazuh_agents_config"); err != nil {
		t.Errorf("wazuh_agents_config: %v", err)
	}
}

func TestAgentsCollector_ErrorEnvelopeReturnsError(t *testing.T) {
	// HTTP 200 but a non-zero Wazuh error envelope must not read as zero agents.
	e, mon := newAgentsExporter(fakeAPIClient{body: []byte(`{"error":403,"message":"permission denied","data":{}}`)})
	if n := testutil.CollectAndCount(e, "wazuh_agents"); n != 0 {
		t.Errorf("error envelope → no series, got %d", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("agents", "collect")); got != 1 {
		t.Errorf("collector_errors_total{agents,collect} = %v, want 1", got)
	}
}

func TestAgentsCollector_ToleratesAbsentFields(t *testing.T) {
	e, _ := newAgentsExporter(fakeAPIClient{body: []byte(`{"data":{"connection":{"active":5}}}`)})
	if n := testutil.CollectAndCount(e, "wazuh_agents"); n != 1 {
		t.Errorf("only active present → 1 series, got %d", n)
	}
	if n := testutil.CollectAndCount(e, "wazuh_agents_count"); n != 0 {
		t.Errorf("absent total → no series, got %d", n)
	}
}

func TestAgentsCollector_ClientErrorEmitsNoSeries(t *testing.T) {
	e, mon := newAgentsExporter(fakeAPIClient{err: errors.New("circuit open")})
	if n := testutil.CollectAndCount(e, "wazuh_agents"); n != 0 {
		t.Errorf("client error → no series, got %d", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("agents", "collect")); got != 1 {
		t.Errorf("collector_errors_total{agents,collect} = %v, want 1", got)
	}
}

func TestAgentsCollector_InvalidJSONEmitsNoSeries(t *testing.T) {
	e, mon := newAgentsExporter(fakeAPIClient{body: []byte(`not json`)})
	if n := testutil.CollectAndCount(e, "wazuh_agents"); n != 0 {
		t.Errorf("invalid JSON → no series, got %d", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("agents", "collect")); got != 1 {
		t.Errorf("collector_errors_total{agents,collect} = %v, want 1", got)
	}
}
