package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func assertFQName(t *testing.T, d *prometheus.Desc, fqName string) {
	t.Helper()
	// Desc.String() embeds the quoted fully-qualified name.
	if !strings.Contains(d.String(), `"`+fqName+`"`) {
		t.Errorf("descriptor %s does not declare fqName %q", d.String(), fqName)
	}
}

func TestDescriptorFQNames(t *testing.T) {
	cases := map[*prometheus.Desc]string{
		UpDesc:                   "wazuh_up",
		BuildInfoDesc:            "wazuh_exporter_build_info",
		AnalysisdEventsReceived:  "wazuh_analysisd_events_received_total",
		AnalysisdEventsDropped:   "wazuh_analysisd_events_dropped_total",
		AnalysisdQueueSize:       "wazuh_analysisd_queue_size",
		AnalysisdQueueCapacity:   "wazuh_analysisd_queue_capacity",
		AnalysisdQueueUsageRatio: "wazuh_analysisd_queue_usage_ratio",
		RemotedTCPSessions:       "wazuh_remoted_tcp_sessions",
		RemotedRecvBytes:         "wazuh_remoted_recv_bytes_total",
		RemotedEvtCount:          "wazuh_remoted_evt_count_total",
		RemotedDiscardedCount:    "wazuh_remoted_discarded_count_total",
		RemotedCtrlMsgCount:      "wazuh_remoted_ctrl_msg_count_total",
		RemotedMsgSent:           "wazuh_remoted_msg_sent_total",
		RemotedQueueSize:         "wazuh_remoted_queue_size",
		RemotedQueueCapacity:     "wazuh_remoted_queue_capacity",
		Agents:                   "wazuh_agents",
		AgentsCount:              "wazuh_agents_count",
		AgentsConfig:             "wazuh_agents_config",
		DBQueriesReceived:        "wazuh_db_queries_received_total",
		DBQueriesBreakdown:       "wazuh_db_queries_breakdown_total",
		ClusterEnabled:           "wazuh_cluster_enabled",
		ClusterNodeInfo:          "wazuh_cluster_node_info",
		ClusterNodeActiveAgents:  "wazuh_cluster_node_active_agents",
	}
	for d, fq := range cases {
		assertFQName(t, d, fq)
	}
}

func TestNamespaces(t *testing.T) {
	if Namespace != "wazuh" || ExporterNamespace != "wazuh_exporter" {
		t.Fatalf("namespaces = %q / %q, want wazuh / wazuh_exporter", Namespace, ExporterNamespace)
	}
}
