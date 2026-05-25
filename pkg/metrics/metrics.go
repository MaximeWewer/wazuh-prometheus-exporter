// Package metrics is the single source of truth for every metric descriptor the
// exporter exposes. Domain collectors (Story 2.2+) reference these descriptors
// and emit values via prometheus.MustNewConstMetric.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Metric namespaces. Domain metrics use Namespace; the exporter's own
// self-metrics use ExporterNamespace.
const (
	Namespace         = "wazuh"
	ExporterNamespace = "wazuh_exporter"
)

// BuildInfoDesc describes the wazuh_exporter_build_info metric — a constant 1
// labelled by version. Descriptors live here as the single source of truth and
// are emitted via prometheus.MustNewConstMetric by the self-metrics collector
// (Story 1.4); collectors never hold long-lived Counter/Gauge vectors.
var BuildInfoDesc = prometheus.NewDesc(
	prometheus.BuildFQName(ExporterNamespace, "", "build_info"),
	"Exporter build information.",
	[]string{"version"}, nil,
)

// UpDesc is the wazuh_up gauge: 1 when the last Wazuh collection succeeded, 0
// when it failed. It carries NO label: it reports the exporter's own collection
// health, not a per-node property, and must be emittable even when the API is
// down (so the node name cannot be discovered). Emitted by the orchestrator.
var UpDesc = prometheus.NewDesc(
	prometheus.BuildFQName(Namespace, "", "up"),
	"Whether the last Wazuh collection succeeded (1) or failed (0).",
	nil, nil,
)

const analysisdSubsystem = "analysisd"

func analysisdDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, analysisdSubsystem, name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// analysisd metric descriptors (all labelled by `node`; queue metrics also by `queue`).
var (
	AnalysisdEventsReceived  = analysisdDesc("events_received_total", "Events received by analysisd.")
	AnalysisdEventsProcessed = analysisdDesc("events_processed_total", "Events processed by analysisd.")
	AnalysisdEventsDropped   = analysisdDesc("events_dropped_total", "Events dropped by analysisd.")
	AnalysisdAlertsWritten   = analysisdDesc("alerts_written_total", "Alerts written by analysisd.")
	AnalysisdFirewallWritten = analysisdDesc("firewall_written_total", "Firewall events written by analysisd.")
	AnalysisdFTSWritten      = analysisdDesc("fts_written_total", "FTS (first-time-seen) entries written by analysisd.")
	AnalysisdQueueSize       = analysisdDesc("queue_size", "Current depth of an analysisd queue (events queued).", "queue")
	AnalysisdQueueCapacity   = analysisdDesc("queue_capacity", "Capacity of an analysisd queue (maximum events).", "queue")
	AnalysisdQueueUsageRatio = analysisdDesc("queue_usage_ratio", "Usage of an analysisd queue, as a ratio in [0,1].", "queue")
	AnalysisdEventsDecoded   = analysisdDesc("events_decoded_total", "Events decoded by analysisd, by module.", "module")
)

const remotedSubsystem = "remoted"

func remotedDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, remotedSubsystem, name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// remoted metric descriptors (all labelled by `node`).
var (
	RemotedTCPSessions        = remotedDesc("tcp_sessions", "Active agent TCP sessions held by remoted.")
	RemotedRecvBytes          = remotedDesc("recv_bytes_total", "Bytes received from agents by remoted.")
	RemotedEvtCount           = remotedDesc("evt_count_total", "Events forwarded by remoted to analysisd.")
	RemotedDiscardedCount     = remotedDesc("discarded_count_total", "Messages discarded by remoted.")
	RemotedCtrlMsgCount       = remotedDesc("ctrl_msg_count_total", "Control messages received by remoted.")
	RemotedMsgSent            = remotedDesc("msg_sent_total", "Messages sent by remoted.")
	RemotedQueueSize          = remotedDesc("queue_size", "Current depth of the remoted receive queue.")
	RemotedQueueCapacity      = remotedDesc("queue_capacity", "Capacity of the remoted receive queue.")
	RemotedSentBytes          = remotedDesc("sent_bytes_total", "Bytes sent by remoted.")
	RemotedDequeuedAfterClose = remotedDesc("dequeued_after_close_total", "Messages dequeued after the agent closed the connection.")
)

// agentsDesc builds a `wazuh_<name>` descriptor (no subsystem, so the base
// `wazuh_agents` name is possible), always prepending the `node` label.
func agentsDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, "", name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// agents metric descriptors (from the Wazuh API, node-labelled). All gauges
// (current counts); AgentsCount avoids a `_total` suffix on a gauge.
var (
	Agents         = agentsDesc("agents", "Number of Wazuh agents by connection status.", "status")
	AgentsCount    = agentsDesc("agents_count", "Total number of Wazuh agents.")
	AgentsConfig   = agentsDesc("agents_config", "Number of Wazuh agents by configuration sync state.", "state")
	AgentsGroup    = agentsDesc("agents_group", "Number of Wazuh agents by group.", "group")
	AgentsVersion  = agentsDesc("agents_version", "Number of Wazuh agents by reported version.", "version")
	AgentsOS       = agentsDesc("agents_os", "Number of Wazuh agents by operating system.", "os")
	AgentsOutdated = agentsDesc("agents_outdated", "Number of Wazuh agents running an outdated version.")
	// LastRegisteredAgentInfo is a constant 1 describing the most recently registered agent.
	LastRegisteredAgentInfo = agentsDesc("last_registered_agent_info", "Metadata of the last registered agent, as a constant 1.", "agent_id", "agent_name", "agent_version", "status")
)

const managerSubsystem = "manager"

func managerDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, managerSubsystem, name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// manager metric descriptors (master-level; labelled by `node`).
var (
	ManagerInfo        = managerDesc("info", "Wazuh manager metadata as a constant 1, labelled by type and version.", "type", "version")
	ManagerMaxAgents   = managerDesc("max_agents", "Maximum number of agents the manager accepts.")
	ManagerConfigValid = managerDesc("config_valid", "Whether the manager configuration validates (1) or has errors (0).")
	// Daily aggregate counters from /manager/stats (the legacy hourly totals file).
	ManagerAlerts   = managerDesc("alerts_total", "Alerts logged by the manager today (sum of hourly totals).")
	ManagerEvents   = managerDesc("events_total", "Events processed by the manager today (sum of hourly totals).")
	ManagerSyscheck = managerDesc("syscheck_total", "Syscheck events logged by the manager today (sum of hourly totals).")
	ManagerFirewall = managerDesc("firewall_total", "Firewall events logged by the manager today (sum of hourly totals).")
	ManagerDaemonUp = managerDesc("daemon_up", "Whether a Wazuh manager daemon is running (1) or not (0).", "daemon")
	ManagerLogs     = managerDesc("logs_total", "Manager log entries by component tag and level.", "tag", "level")
	// Historical alert-volume profiles from /…/stats/hourly and /…/stats/weekly.
	ManagerHourlyAlertsAvg = managerDesc("hourly_alerts_average", "Average alerts per hour of the day (0-23), from Wazuh's hourly stats profile.", "hour")
	ManagerWeeklyAlertsAvg = managerDesc("weekly_alerts_average", "Average alerts per weekday and hour, from Wazuh's weekly stats profile.", "day", "hour")
)

const dbSubsystem = "db"

func dbDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, dbSubsystem, name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// wazuh-db metric descriptors (from the Wazuh API, node-labelled). Cumulative
// query counters → CounterValue (reset-safe).
var (
	DBQueriesReceived  = dbDesc("queries_received_total", "Total queries received by wazuh-db.")
	DBQueriesBreakdown = dbDesc("queries_breakdown_total", "Queries received by wazuh-db, by category.", "category")
)

const clusterSubsystem = "cluster"

func clusterDesc(name, help string, extraLabels ...string) *prometheus.Desc {
	return prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, clusterSubsystem, name),
		help,
		append([]string{"node"}, extraLabels...), nil,
	)
}

// cluster metric descriptors (from the Wazuh API, node-labelled). All gauges.
var (
	ClusterEnabled          = clusterDesc("enabled", "Whether Wazuh cluster mode is enabled (1) or standalone (0).")
	ClusterNodeInfo         = clusterDesc("node_info", "Cluster node metadata as a constant 1, labelled by type and version.", "type", "version")
	ClusterNodeActiveAgents = clusterDesc("node_active_agents", "Active agents reported for a cluster node.")
	ClusterRulesetSynced    = clusterDesc("ruleset_synced", "Whether a cluster node's ruleset is synchronized (1) or not (0).")
)
