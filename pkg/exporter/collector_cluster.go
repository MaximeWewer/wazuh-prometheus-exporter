package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

// ClusterCollector detects cluster mode and, when clustered, discovers nodes,
// exposes per-node health, and emits each worker's daemon stats — all from the
// master via the Wazuh API. It makes no per-node calls on a standalone manager
// (only the single /cluster/status detection call).
//
// Known limitation: worker logcollector metrics are NOT exposed. The cluster
// daemon-stats API does not surface logcollector for workers, so wazuh_logcollector_*
// is master-only (from the local .state). This is by design, not an error.
type ClusterCollector struct {
	client api.APIClient
	node   string // resolved per scrape from /cluster/local/info
	log    zerolog.Logger
}

// NewClusterCollector builds the cluster collector on the (decorated) API client.
func NewClusterCollector(client api.APIClient, log zerolog.Logger) *ClusterCollector {
	return &ClusterCollector{client: client, log: log}
}

// Name implements Collector.
func (c *ClusterCollector) Name() string { return "cluster" }

type clusterLocalInfo struct {
	Data struct {
		AffectedItems []struct {
			Node string `json:"node"`
		} `json:"affected_items"`
	} `json:"data"`
}

// localNodeName resolves the exporter's local Wazuh node name from
// /cluster/local/info (works in cluster and standalone mode). It is the `node`
// label for the cluster-level gauge, the agent metrics, and — in standalone mode
// — the per-node metrics. Falls back to "manager" when the endpoint is
// unavailable (e.g. the API is down, in which case no metrics emit anyway).
func localNodeName(ctx context.Context, client api.APIClient) string {
	const fallback = "manager"
	b, err := client.Get(ctx, "/cluster/local/info")
	if err != nil {
		return fallback
	}
	var li clusterLocalInfo
	if json.Unmarshal(b, &li) == nil && len(li.Data.AffectedItems) > 0 && li.Data.AffectedItems[0].Node != "" {
		return li.Data.AffectedItems[0].Node
	}
	return fallback
}

type clusterStatus struct {
	Error   *int64  `json:"error"`
	Message *string `json:"message"`
	Data    struct {
		Enabled string `json:"enabled"`
		Running string `json:"running"`
	} `json:"data"`
}

type clusterHealth struct {
	Error   *int64  `json:"error"`
	Message *string `json:"message"`
	Data    struct {
		// /cluster/healthcheck nests node fields under `info`.
		AffectedItems []struct {
			Info struct {
				Name         string `json:"name"`
				Type         string `json:"type"`
				Version      string `json:"version"`
				ActiveAgents *int64 `json:"n_active_agents"`
			} `json:"info"`
		} `json:"affected_items"`
	} `json:"data"`
}

// envelopeError returns an error if the Wazuh response carries a non-zero error
// code (sometimes returned with HTTP 200).
func envelopeError(code *int64, message *string, ctx string) error {
	if code != nil && *code != 0 {
		msg := ""
		if message != nil {
			msg = *message
		}
		return fmt.Errorf("%s: Wazuh API error %d: %s", ctx, *code, msg)
	}
	return nil
}

// Collect detects cluster mode via /cluster/status; when enabled it discovers
// nodes and their health via /cluster/healthcheck. A standalone manager emits
// only wazuh_cluster_enabled=0 and makes no further cluster calls.
func (c *ClusterCollector) Collect(ctx context.Context, ch chan<- prometheus.Metric) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Resolve the local node name from the API (replaces a configured value).
	// Scrapes are serialized by the orchestrator, so this field write is safe.
	c.node = localNodeName(ctx, c.client)

	body, err := c.client.Get(ctx, "/cluster/status")
	if err != nil {
		return fmt.Errorf("cluster status: %w", err)
	}
	var st clusterStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("decoding cluster status: %w", err)
	}
	if err := envelopeError(st.Error, st.Message, "cluster status"); err != nil {
		return err
	}

	enabled := st.Data.Enabled == "yes"
	enabledVal := 0.0
	if enabled {
		enabledVal = 1
	}
	ch <- prometheus.MustNewConstMetric(metrics.ClusterEnabled, prometheus.GaugeValue, enabledVal, c.node)

	if !enabled {
		// Standalone: validate + collect the single manager node via /manager/*.
		c.collectConfigValid(ctx, ch)
		c.collectNode(ctx, ch, c.node, "/manager")
		return nil
	}

	body, err = c.client.Get(ctx, "/cluster/healthcheck")
	if err != nil {
		return fmt.Errorf("cluster healthcheck: %w", err)
	}
	var h clusterHealth
	if err := json.Unmarshal(body, &h); err != nil {
		return fmt.Errorf("decoding cluster healthcheck: %w", err)
	}
	if err := envelopeError(h.Error, h.Message, "cluster healthcheck"); err != nil {
		return err
	}

	seen := make(map[string]struct{})
	for _, it := range h.Data.AffectedItems {
		info := it.Info
		if info.Name == "" {
			continue
		}
		if _, dup := seen[info.Name]; dup {
			continue // a repeated node name would emit a duplicate series and fail registry.Gather
		}
		seen[info.Name] = struct{}{}
		ch <- prometheus.MustNewConstMetric(metrics.ClusterNodeInfo, prometheus.GaugeValue, 1, info.Name, info.Type, info.Version)
		if info.ActiveAgents != nil && *info.ActiveAgents >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.ClusterNodeActiveAgents, prometheus.GaugeValue, float64(*info.ActiveAgents), info.Name)
		}
		// Every node (master included) is collected through the cluster API.
		c.collectNode(ctx, ch, info.Name, "/cluster/"+url.PathEscape(info.Name))
	}
	// One call validates the whole cluster, returning per-node status.
	c.collectClusterConfigValid(ctx, ch)
	c.collectRulesetSync(ctx, ch)
	return nil
}

// collectNode collects one node's manager-style metrics from base (/manager for a
// standalone manager, or /cluster/<node> when clustered): daemon stats, daemon
// up/down, log levels, info and daily totals. All best-effort.
func (c *ClusterCollector) collectNode(ctx context.Context, ch chan<- prometheus.Metric, node, base string) {
	get := func(path string) []byte {
		b, err := c.client.Get(ctx, base+path)
		if err != nil {
			c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
				Str("node", node).Str("path", base+path).Err(err).Msg("node metric unavailable; skipping")
			return nil
		}
		return b
	}
	if b := get("/daemons/stats"); b != nil {
		if err := emitDaemonsStats(ch, node, b); err != nil {
			c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
				Str("node", node).Err(err).Msg("daemons stats; skipping")
		}
	}
	if b := get("/status"); b != nil {
		emitDaemonUp(ch, node, b)
	}
	if b := get("/logs/summary"); b != nil {
		emitManagerLogs(ch, node, b)
	}
	if b := get("/info"); b != nil {
		emitManagerInfo(ch, node, b)
	}
	if b := get("/stats"); b != nil {
		emitManagerDailyStats(ch, node, b)
	}
	if b := get("/stats/hourly"); b != nil {
		emitHourlyStats(ch, node, b)
	}
	if b := get("/stats/weekly"); b != nil {
		emitWeeklyStats(ch, node, b)
	}
}

// collectConfigValid emits config_valid{node} for the standalone manager from
// /manager/configuration/validation (single node, labelled with the configured node).
func (c *ClusterCollector) collectConfigValid(ctx context.Context, ch chan<- prometheus.Metric) {
	body, err := c.client.Get(ctx, "/manager/configuration/validation")
	if err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
			Err(err).Msg("configuration validation unavailable; skipping")
		return
	}
	emitConfigValid(ch, c.node, body)
}

// collectClusterConfigValid emits config_valid{node} for every node from
// /cluster/configuration/validation — one call validates the whole cluster
// (per-node status in affected_items). There is no per-node validation path
// (/cluster/<node>/configuration/validation returns 404). Best-effort.
func (c *ClusterCollector) collectClusterConfigValid(ctx context.Context, ch chan<- prometheus.Metric) {
	body, err := c.client.Get(ctx, "/cluster/configuration/validation")
	if err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
			Err(err).Msg("cluster configuration validation unavailable; skipping")
		return
	}
	emitClusterConfigValid(ch, body)
}

type rulesetSync struct {
	Error *int64 `json:"error"`
	Data  struct {
		AffectedItems []struct {
			Name   *string `json:"name"`
			Synced *bool   `json:"synced"`
		} `json:"affected_items"`
	} `json:"data"`
}

// collectRulesetSync emits ruleset_synced{node} from /cluster/ruleset/synchronization.
// The endpoint covers the whole ruleset (rules + decoders + CDB lists) as one
// synced flag per node; Wazuh exposes no separate per-decoder sync state.
// Best-effort and clustered-only (the caller already returned for standalone).
func (c *ClusterCollector) collectRulesetSync(ctx context.Context, ch chan<- prometheus.Metric) {
	body, err := c.client.Get(ctx, "/cluster/ruleset/synchronization")
	if err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
			Err(err).Msg("cluster ruleset synchronization unavailable; skipping")
		return
	}
	var rs rulesetSync
	if err := json.Unmarshal(body, &rs); err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "cluster").
			Err(err).Msg("decoding cluster ruleset synchronization")
		return
	}
	if rs.Error != nil && *rs.Error != 0 {
		return
	}
	seen := make(map[string]struct{})
	for _, it := range rs.Data.AffectedItems {
		if it.Name == nil || it.Synced == nil {
			continue
		}
		if _, dup := seen[*it.Name]; dup {
			continue
		}
		seen[*it.Name] = struct{}{}
		v := 0.0
		if *it.Synced {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(metrics.ClusterRulesetSynced, prometheus.GaugeValue, v, *it.Name)
	}
}
