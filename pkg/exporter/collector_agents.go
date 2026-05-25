package exporter

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/wazuh/api"
)

// AgentsCollector emits agent-fleet metrics from the Wazuh API
// (GET /agents/summary/status for status counts, GET /overview/agents for the
// group/version breakdown and the last registered agent). It is driven through
// the cache→breaker→client chain supplied at construction.
type AgentsCollector struct {
	client api.APIClient
	node   string // resolved per scrape from /cluster/local/info
	log    zerolog.Logger
}

// NewAgentsCollector builds the agents collector on the (decorated) Wazuh API client.
func NewAgentsCollector(client api.APIClient, log zerolog.Logger) *AgentsCollector {
	return &AgentsCollector{client: client, log: log}
}

// Name implements Collector.
func (c *AgentsCollector) Name() string { return "agents" }

// agentsSummary is the tolerant shape of GET /agents/summary/status. Pointer
// fields let absent keys be skipped rather than emitted as a fabricated 0.
// Error/Message catch the Wazuh envelope returned (sometimes with HTTP 200) on
// an API/RBAC failure, so it is not silently parsed as a zero-agent fleet.
type agentsSummary struct {
	Error   *int64  `json:"error"`
	Message *string `json:"message"`
	Data    struct {
		Connection struct {
			Active         *int64 `json:"active"`
			Disconnected   *int64 `json:"disconnected"`
			NeverConnected *int64 `json:"never_connected"`
			Pending        *int64 `json:"pending"`
			Total          *int64 `json:"total"`
		} `json:"connection"`
		Configuration struct {
			Synced    *int64 `json:"synced"`
			NotSynced *int64 `json:"not_synced"`
		} `json:"configuration"`
	} `json:"data"`
}

// Collect fetches the agent summary and emits gauges. A transport/API error or
// an undecodable body is returned to the orchestrator (which counts it and omits
// these series).
func (c *AgentsCollector) Collect(ctx context.Context, ch chan<- prometheus.Metric) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Resolve the `node` label from the API (replaces a configured value).
	// Scrapes are serialized by the orchestrator, so this field write is safe.
	c.node = localNodeName(ctx, c.client)

	body, err := c.client.Get(ctx, "/agents/summary/status")
	if err != nil {
		return fmt.Errorf("agents summary: %w", err)
	}
	var s agentsSummary
	if err := json.Unmarshal(body, &s); err != nil {
		return fmt.Errorf("decoding agents summary: %w", err)
	}
	// Wazuh signals API/RBAC failures with a non-zero `error` even on HTTP 200;
	// surface it rather than reporting an empty fleet.
	if s.Error != nil && *s.Error != 0 {
		msg := ""
		if s.Message != nil {
			msg = *s.Message
		}
		return fmt.Errorf("agents summary: Wazuh API error %d: %s", *s.Error, msg)
	}

	conn := s.Data.Connection
	status := func(v *int64, label string) {
		if v != nil && *v >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.Agents, prometheus.GaugeValue, float64(*v), c.node, label)
		}
	}
	status(conn.Active, "active")
	status(conn.Disconnected, "disconnected")
	status(conn.NeverConnected, "never_connected")
	status(conn.Pending, "pending")
	if conn.Total != nil && *conn.Total >= 0 {
		ch <- prometheus.MustNewConstMetric(metrics.AgentsCount, prometheus.GaugeValue, float64(*conn.Total), c.node)
	}

	cfg := s.Data.Configuration
	state := func(v *int64, label string) {
		if v != nil && *v >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.AgentsConfig, prometheus.GaugeValue, float64(*v), c.node, label)
		}
	}
	state(cfg.Synced, "synced")
	state(cfg.NotSynced, "not_synced")

	// Group/version/OS breakdown + last registered agent come from /overview/agents,
	// and the outdated count from /agents/outdated. Best-effort: a failure here must
	// not drop the status metrics emitted above.
	c.collectOverview(ctx, ch)
	c.collectOutdated(ctx, ch)
	return nil
}

type agentsOverview struct {
	Error   *int64  `json:"error"`
	Message *string `json:"message"`
	Data    struct {
		Groups []struct {
			Name  *string `json:"name"`
			Count *int64  `json:"count"`
		} `json:"groups"`
		AgentVersion []struct {
			Version *string `json:"version"`
			Count   *int64  `json:"count"`
		} `json:"agent_version"`
		AgentOS []struct {
			OS struct {
				Name     *string `json:"name"`
				Platform *string `json:"platform"`
			} `json:"os"`
			Count *int64 `json:"count"`
		} `json:"agent_os"`
		LastRegisteredAgent []struct {
			ID      *string `json:"id"`
			Name    *string `json:"name"`
			Version *string `json:"version"`
			Status  *string `json:"status"`
		} `json:"last_registered_agent"`
	} `json:"data"`
}

func (c *AgentsCollector) collectOverview(ctx context.Context, ch chan<- prometheus.Metric) {
	body, err := c.client.Get(ctx, "/overview/agents")
	if err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "agents").
			Err(err).Msg("agents overview unavailable; skipping group/version breakdown")
		return
	}
	var o agentsOverview
	if err := json.Unmarshal(body, &o); err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "agents").
			Err(err).Msg("decoding agents overview")
		return
	}
	if o.Error != nil && *o.Error != 0 {
		return
	}

	// Dedup by label value: a repeated group/version in one response would
	// otherwise emit a duplicate (desc, labelvalues) series and fail Gather (500).
	groups := map[string]float64{}
	for _, g := range o.Data.Groups {
		if g.Name != nil && g.Count != nil && *g.Count >= 0 {
			groups[*g.Name] += float64(*g.Count)
		}
	}
	for name, count := range groups {
		ch <- prometheus.MustNewConstMetric(metrics.AgentsGroup, prometheus.GaugeValue, count, c.node, name)
	}
	versions := map[string]float64{}
	for _, v := range o.Data.AgentVersion {
		if v.Version != nil && v.Count != nil && *v.Count >= 0 {
			versions[*v.Version] += float64(*v.Count)
		}
	}
	for version, count := range versions {
		ch <- prometheus.MustNewConstMetric(metrics.AgentsVersion, prometheus.GaugeValue, count, c.node, version)
	}
	oses := map[string]float64{}
	for _, o := range o.Data.AgentOS {
		if o.Count == nil || *o.Count < 0 {
			continue
		}
		name := strOr(o.OS.Name)
		if name == "" {
			name = strOr(o.OS.Platform)
		}
		if name != "" {
			oses[name] += float64(*o.Count)
		}
	}
	for os, count := range oses {
		ch <- prometheus.MustNewConstMetric(metrics.AgentsOS, prometheus.GaugeValue, count, c.node, os)
	}
	if len(o.Data.LastRegisteredAgent) > 0 {
		a := o.Data.LastRegisteredAgent[0]
		if a.ID != nil || a.Name != nil {
			ch <- prometheus.MustNewConstMetric(metrics.LastRegisteredAgentInfo, prometheus.GaugeValue, 1,
				c.node, strOr(a.ID), strOr(a.Name), strOr(a.Version), strOr(a.Status))
		}
	}
}

type agentsOutdated struct {
	Error *int64 `json:"error"`
	Data  struct {
		TotalAffectedItems *int64 `json:"total_affected_items"`
	} `json:"data"`
}

// collectOutdated emits agents_outdated from /agents/outdated. Best-effort.
func (c *AgentsCollector) collectOutdated(ctx context.Context, ch chan<- prometheus.Metric) {
	body, err := c.client.Get(ctx, "/agents/outdated")
	if err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "agents").
			Err(err).Msg("agents outdated unavailable")
		return
	}
	var o agentsOutdated
	if err := json.Unmarshal(body, &o); err != nil {
		c.log.Warn().Str("component", "exporter").Str("collector", "agents").
			Err(err).Msg("decoding agents outdated")
		return
	}
	if o.Error != nil && *o.Error != 0 {
		return
	}
	if o.Data.TotalAffectedItems != nil && *o.Data.TotalAffectedItems >= 0 {
		ch <- prometheus.MustNewConstMetric(metrics.AgentsOutdated, prometheus.GaugeValue, float64(*o.Data.TotalAffectedItems), c.node)
	}
}

func strOr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
