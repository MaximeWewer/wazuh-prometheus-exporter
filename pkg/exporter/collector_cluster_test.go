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

// fakeRouter is an api.APIClient that responds per request path and counts calls.
type fakeRouter struct {
	resp  map[string]string
	err   error
	calls map[string]int
}

func newRouter(resp map[string]string) *fakeRouter {
	return &fakeRouter{resp: resp, calls: map[string]int{}}
}

func (f *fakeRouter) Get(_ context.Context, path string) ([]byte, error) {
	f.calls[path]++
	if f.err != nil {
		return nil, f.err
	}
	b, ok := f.resp[path]
	if !ok {
		return nil, errors.New("no route: " + path)
	}
	return []byte(b), nil
}

func newClusterExporter(client *fakeRouter) (*Exporter, *monitoring.Metrics) {
	mon := monitoring.New("test", time.Now())
	return New(logger.New("error"), mon, time.Second, NewClusterCollector(client, logger.New("error"))), mon
}

func TestClusterCollector_StandaloneNoHealthcheck(t *testing.T) {
	r := newRouter(map[string]string{"/cluster/status": `{"data":{"enabled":"no","running":"no"}}`})
	e, _ := newClusterExporter(r)

	exp := `
# HELP wazuh_cluster_enabled Whether Wazuh cluster mode is enabled (1) or standalone (0).
# TYPE wazuh_cluster_enabled gauge
wazuh_cluster_enabled{node="manager"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(exp), "wazuh_cluster_enabled"); err != nil {
		t.Errorf("cluster_enabled: %v", err)
	}
	if n := testutil.CollectAndCount(e, "wazuh_cluster_node_info"); n != 0 {
		t.Errorf("standalone → no node_info, got %d", n)
	}
	if r.calls["/cluster/healthcheck"] != 0 {
		t.Errorf("standalone must NOT call /cluster/healthcheck, got %d calls", r.calls["/cluster/healthcheck"])
	}
}

func TestClusterCollector_ClusteredDiscoversNodes(t *testing.T) {
	r := newRouter(map[string]string{
		"/cluster/status": `{"data":{"enabled":"yes","running":"yes"}}`,
		"/cluster/healthcheck": `{"data":{"affected_items":[
			{"info":{"name":"master01","type":"master","version":"4.14","n_active_agents":40}},
			{"info":{"name":"worker01","type":"worker","version":"4.14","n_active_agents":10}}
		]}}`,
	})
	e, _ := newClusterExporter(r)

	expEnabled := `
# HELP wazuh_cluster_enabled Whether Wazuh cluster mode is enabled (1) or standalone (0).
# TYPE wazuh_cluster_enabled gauge
wazuh_cluster_enabled{node="manager"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expEnabled), "wazuh_cluster_enabled"); err != nil {
		t.Errorf("cluster_enabled: %v", err)
	}
	expInfo := `
# HELP wazuh_cluster_node_info Cluster node metadata as a constant 1, labelled by type and version.
# TYPE wazuh_cluster_node_info gauge
wazuh_cluster_node_info{node="master01",type="master",version="4.14"} 1
wazuh_cluster_node_info{node="worker01",type="worker",version="4.14"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expInfo), "wazuh_cluster_node_info"); err != nil {
		t.Errorf("cluster_node_info: %v", err)
	}
	if n := testutil.CollectAndCount(e, "wazuh_cluster_node_active_agents"); n != 2 {
		t.Errorf("active_agents per node = %d, want 2", n)
	}
}

func TestClusterCollector_DeduplicatesNodeName(t *testing.T) {
	// A node listed twice must collapse to one series, not fail registry.Gather.
	r := newRouter(map[string]string{
		"/cluster/status": `{"data":{"enabled":"yes"}}`,
		"/cluster/healthcheck": `{"data":{"affected_items":[
			{"info":{"name":"worker01","type":"worker","version":"4.14","n_active_agents":10}},
			{"info":{"name":"worker01","type":"worker","version":"4.14","n_active_agents":99}}
		]}}`,
	})
	e, _ := newClusterExporter(r)
	if n := testutil.CollectAndCount(e, "wazuh_cluster_node_info"); n != 1 {
		t.Errorf("duplicate node name must collapse to 1 series, got %d", n)
	}
	if n := testutil.CollectAndCount(e, "wazuh_cluster_node_active_agents"); n != 1 {
		t.Errorf("duplicate node name must collapse to 1 active_agents series, got %d", n)
	}
}

func TestClusterCollector_WorkerDaemonStats(t *testing.T) {
	r := newRouter(map[string]string{
		"/cluster/status": `{"data":{"enabled":"yes"}}`,
		"/cluster/healthcheck": `{"data":{"affected_items":[
			{"info":{"name":"master01","type":"master","version":"4.14"}},
			{"info":{"name":"worker01","type":"worker","version":"4.14"}},
			{"info":{"name":"worker02","type":"worker","version":"4.14"}}
		]}}`,
		"/cluster/worker01/daemons/stats": `{"data":{"affected_items":[{"name":"wazuh-db","metrics":{"queries":{"received":700}}}]}}`,
		"/cluster/worker02/daemons/stats": `{"data":{"affected_items":[{"name":"wazuh-db","metrics":{"queries":{"received":300}}}]}}`,
		"/cluster/worker01/status":        `{"data":{"affected_items":[{"wazuh-analysisd":"running","wazuh-remoted":"stopped"}]}}`,
		"/cluster/worker02/status":        `{"data":{"affected_items":[{"wazuh-analysisd":"running"}]}}`,
	})
	e, _ := newClusterExporter(r)

	exp := `
# HELP wazuh_db_queries_received_total Total queries received by wazuh-db.
# TYPE wazuh_db_queries_received_total counter
wazuh_db_queries_received_total{node="worker01"} 700
wazuh_db_queries_received_total{node="worker02"} 300
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(exp), "wazuh_db_queries_received_total"); err != nil {
		t.Errorf("per-worker queries: %v", err)
	}
	// Every node is collected via /cluster/<node>/* — including the master.
	if r.calls["/cluster/master01/daemons/stats"] != 1 {
		t.Errorf("master daemon stats should be queried via the cluster API, got %d calls", r.calls["/cluster/master01/daemons/stats"])
	}
	// Per-worker daemon health from /cluster/<node>/status.
	expDaemon := `
# HELP wazuh_manager_daemon_up Whether a Wazuh manager daemon is running (1) or not (0).
# TYPE wazuh_manager_daemon_up gauge
wazuh_manager_daemon_up{daemon="wazuh-analysisd",node="worker01"} 1
wazuh_manager_daemon_up{daemon="wazuh-analysisd",node="worker02"} 1
wazuh_manager_daemon_up{daemon="wazuh-remoted",node="worker01"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expDaemon), "wazuh_manager_daemon_up"); err != nil {
		t.Errorf("per-worker daemon_up: %v", err)
	}
}

func TestClusterCollector_ClusterConfigValidPerNode(t *testing.T) {
	// /cluster/configuration/validation validates the whole cluster in one call,
	// returning a per-node status — emit config_valid for each node.
	r := newRouter(map[string]string{
		"/cluster/status": `{"data":{"enabled":"yes"}}`,
		"/cluster/healthcheck": `{"data":{"affected_items":[
			{"info":{"name":"master01","type":"master","version":"4.14"}},
			{"info":{"name":"worker01","type":"worker","version":"4.14"}}
		]}}`,
		"/cluster/configuration/validation": `{"data":{"total_failed_items":1,"affected_items":[
			{"name":"master01","status":"OK"},
			{"name":"worker01","status":"KO"}
		]}}`,
	})
	e, _ := newClusterExporter(r)

	exp := `
# HELP wazuh_manager_config_valid Whether the manager configuration validates (1) or has errors (0).
# TYPE wazuh_manager_config_valid gauge
wazuh_manager_config_valid{node="master01"} 1
wazuh_manager_config_valid{node="worker01"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(exp), "wazuh_manager_config_valid"); err != nil {
		t.Errorf("per-node config_valid: %v", err)
	}
	// The per-node validation path does not exist; only the cluster-wide one is used.
	if r.calls["/cluster/master01/configuration/validation"] != 0 {
		t.Errorf("must not call a per-node validation path, got %d", r.calls["/cluster/master01/configuration/validation"])
	}
}

func TestClusterCollector_OneWorkerFailsOthersEmit(t *testing.T) {
	// worker02 has no daemon-stats route (→ fetch error); worker01 must still emit
	// and the collector must not fail.
	r := newRouter(map[string]string{
		"/cluster/status": `{"data":{"enabled":"yes"}}`,
		"/cluster/healthcheck": `{"data":{"affected_items":[
			{"info":{"name":"worker01","type":"worker","version":"4.14"}},
			{"info":{"name":"worker02","type":"worker","version":"4.14"}}
		]}}`,
		"/cluster/worker01/daemons/stats": `{"data":{"affected_items":[{"name":"wazuh-db","metrics":{"queries":{"received":700}}}]}}`,
	})
	e, mon := newClusterExporter(r)

	if n := testutil.CollectAndCount(e, "wazuh_db_queries_received_total"); n != 1 {
		t.Errorf("healthy worker must still emit, got %d series", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("cluster", "collect")); got != 0 {
		t.Errorf("one worker failing must NOT fail the collector, got %v errors", got)
	}
}

func TestClusterCollector_ErrorEnvelopeReturnsError(t *testing.T) {
	r := newRouter(map[string]string{"/cluster/status": `{"error":4,"message":"no permission","data":{}}`})
	e, mon := newClusterExporter(r)
	if n := testutil.CollectAndCount(e, "wazuh_cluster_enabled"); n != 0 {
		t.Errorf("error envelope → no series, got %d", n)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("cluster", "collect")); got != 1 {
		t.Errorf("collector_errors_total{cluster,collect} = %v, want 1", got)
	}
}

func TestClusterCollector_ClientErrorAndInvalidJSON(t *testing.T) {
	for _, tc := range []struct {
		name   string
		router *fakeRouter
	}{
		{"client error", &fakeRouter{err: errors.New("circuit open"), calls: map[string]int{}}},
		{"invalid json", newRouter(map[string]string{"/cluster/status": "not json"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, mon := newClusterExporter(tc.router)
			if n := testutil.CollectAndCount(e, "wazuh_cluster_enabled"); n != 0 {
				t.Errorf("%s → no series, got %d", tc.name, n)
			}
			if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("cluster", "collect")); got != 1 {
				t.Errorf("%s: collector_errors = %v, want 1", tc.name, got)
			}
		})
	}
}
