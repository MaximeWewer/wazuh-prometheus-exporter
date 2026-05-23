package exporter

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const daemonsBody = `{"data":{"affected_items":[
  {"name":"wazuh-analysisd","metrics":{
    "events":{"received":100,"processed":90,
      "received_breakdown":{
        "decoded_breakdown":{"dbsync":50,"modules_breakdown":{"syscheck":4,"sca":2,"logcollector_breakdown":{"eventchannel":3}}},
        "dropped_breakdown":{"modules_breakdown":{"syscheck":1}}},
      "written_breakdown":{"alerts":10,"firewall":0,"fts":1}},
    "queues":{"syscheck":{"size":16384,"usage":8192}}}},
  {"name":"wazuh-remoted","metrics":{
    "bytes":{"received":500,"sent":300},"tcp_sessions":3,
    "messages":{"received_breakdown":{"event":80,"control":5,"discarded":0,"dequeued_after":0},
      "sent_breakdown":{"ack":5,"shared":10}},
    "queues":{"received":{"size":131072,"usage":0}}}},
  {"name":"wazuh-db","metrics":{"queries":{"received":1000,
    "received_breakdown":{"global":{"queries":600},"agent":{"queries":400}}}}}
]}}`

// Drives the standalone path of the cluster collector (/manager/daemons/stats).
func newNodeExporter(extra map[string]string) *Exporter {
	resp := map[string]string{"/cluster/status": `{"data":{"enabled":"no"}}`}
	for k, v := range extra {
		resp[k] = v
	}
	e, _ := newClusterExporter(newRouter(resp))
	return e
}

func TestNode_DaemonsAnalysisd(t *testing.T) {
	e := newNodeExporter(map[string]string{"/manager/daemons/stats": daemonsBody})
	exp := `
# HELP wazuh_analysisd_events_received_total Events received by analysisd.
# TYPE wazuh_analysisd_events_received_total counter
wazuh_analysisd_events_received_total{node="manager"} 100
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(exp), "wazuh_analysisd_events_received_total"); err != nil {
		t.Errorf("events_received: %v", err)
	}
	expDrop := `
# HELP wazuh_analysisd_events_dropped_total Events dropped by analysisd.
# TYPE wazuh_analysisd_events_dropped_total counter
wazuh_analysisd_events_dropped_total{node="manager"} 1
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expDrop), "wazuh_analysisd_events_dropped_total"); err != nil {
		t.Errorf("events_dropped (summed): %v", err)
	}
	expRatio := `
# HELP wazuh_analysisd_queue_usage_ratio Usage of an analysisd queue, as a ratio in [0,1].
# TYPE wazuh_analysisd_queue_usage_ratio gauge
wazuh_analysisd_queue_usage_ratio{node="manager",queue="syscheck"} 0.5
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expRatio), "wazuh_analysisd_queue_usage_ratio"); err != nil {
		t.Errorf("queue_usage_ratio: %v", err)
	}
	// queue_size is the current depth (usage); queue_capacity is the total (size).
	expQueue := `
# HELP wazuh_analysisd_queue_size Current depth of an analysisd queue (events queued).
# TYPE wazuh_analysisd_queue_size gauge
wazuh_analysisd_queue_size{node="manager",queue="syscheck"} 8192
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expQueue), "wazuh_analysisd_queue_size"); err != nil {
		t.Errorf("queue_size (depth): %v", err)
	}
	expCap := `
# HELP wazuh_analysisd_queue_capacity Capacity of an analysisd queue (maximum events).
# TYPE wazuh_analysisd_queue_capacity gauge
wazuh_analysisd_queue_capacity{node="manager",queue="syscheck"} 16384
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expCap), "wazuh_analysisd_queue_capacity"); err != nil {
		t.Errorf("queue_capacity: %v", err)
	}
	expDecoded := `
# HELP wazuh_analysisd_events_decoded_total Events decoded by analysisd, by module.
# TYPE wazuh_analysisd_events_decoded_total counter
wazuh_analysisd_events_decoded_total{module="dbsync",node="manager"} 50
wazuh_analysisd_events_decoded_total{module="logcollector_eventchannel",node="manager"} 3
wazuh_analysisd_events_decoded_total{module="sca",node="manager"} 2
wazuh_analysisd_events_decoded_total{module="syscheck",node="manager"} 4
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expDecoded), "wazuh_analysisd_events_decoded_total"); err != nil {
		t.Errorf("events_decoded (flattened): %v", err)
	}
}

func TestNode_DaemonsRemotedAndDB(t *testing.T) {
	e := newNodeExporter(map[string]string{"/manager/daemons/stats": daemonsBody})
	expRem := `
# HELP wazuh_remoted_msg_sent_total Messages sent by remoted.
# TYPE wazuh_remoted_msg_sent_total counter
wazuh_remoted_msg_sent_total{node="manager"} 15
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expRem), "wazuh_remoted_msg_sent_total"); err != nil {
		t.Errorf("remoted msg_sent (summed): %v", err)
	}
	if n := testutil.CollectAndCount(e, "wazuh_remoted_tcp_sessions"); n != 1 {
		t.Errorf("tcp_sessions → 1 series, got %d", n)
	}
	// queue_size = current depth (usage=0); queue_capacity = total (size=131072).
	expQueue := `
# HELP wazuh_remoted_queue_size Current depth of the remoted receive queue.
# TYPE wazuh_remoted_queue_size gauge
wazuh_remoted_queue_size{node="manager"} 0
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expQueue), "wazuh_remoted_queue_size"); err != nil {
		t.Errorf("remoted queue_size (depth): %v", err)
	}
	expCap := `
# HELP wazuh_remoted_queue_capacity Capacity of the remoted receive queue.
# TYPE wazuh_remoted_queue_capacity gauge
wazuh_remoted_queue_capacity{node="manager"} 131072
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expCap), "wazuh_remoted_queue_capacity"); err != nil {
		t.Errorf("remoted queue_capacity: %v", err)
	}
	expDB := `
# HELP wazuh_db_queries_breakdown_total Queries received by wazuh-db, by category.
# TYPE wazuh_db_queries_breakdown_total counter
wazuh_db_queries_breakdown_total{category="agent",node="manager"} 400
wazuh_db_queries_breakdown_total{category="global",node="manager"} 600
`
	if err := testutil.CollectAndCompare(e, strings.NewReader(expDB), "wazuh_db_queries_breakdown_total"); err != nil {
		t.Errorf("db breakdown: %v", err)
	}
}
