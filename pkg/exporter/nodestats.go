package exporter

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
)

// This file holds the shared per-node emitters for the manager-style endpoints
// (status, logs/summary, info, stats). They are driven by the cluster collector:
// for a standalone manager via /manager/<x>, and for each cluster node via
// /cluster/<node>/<x>. Each takes the resolved `node` label and a response body.

type managerStatus struct {
	Error *int64 `json:"error"`
	Data  struct {
		AffectedItems []map[string]string `json:"affected_items"`
	} `json:"data"`
}

// emitDaemonUp emits daemon_up{node,daemon} from a /…/status body (daemon->state).
func emitDaemonUp(ch chan<- prometheus.Metric, node string, body []byte) {
	var ms managerStatus
	if json.Unmarshal(body, &ms) != nil {
		return
	}
	if ms.Error != nil && *ms.Error != 0 {
		return
	}
	// Dedup by daemon name across all affected_items: a daemon repeated in two
	// elements would emit a duplicate (desc, labelvalues) series and fail Gather
	// (500). Iterating every item (not just [0]) also avoids dropping daemons if
	// Wazuh ever splits the list across elements.
	seen := make(map[string]struct{})
	for _, item := range ms.Data.AffectedItems {
		for daemon, state := range item {
			if _, dup := seen[daemon]; dup {
				continue
			}
			seen[daemon] = struct{}{}
			up := 0.0
			if strings.EqualFold(state, "running") {
				up = 1
			}
			ch <- prometheus.MustNewConstMetric(metrics.ManagerDaemonUp, prometheus.GaugeValue, up, node, daemon)
		}
	}
}

type managerLogsSummary struct {
	Error *int64 `json:"error"`
	Data  struct {
		// Each item is a single-key object: {"<tag>": {"info":N,"error":N,...}}.
		AffectedItems []map[string]map[string]float64 `json:"affected_items"`
	} `json:"data"`
}

// emitManagerLogs emits logs_total{node,tag,level} from a /…/logs/summary body
// (the "all" pseudo-level is dropped to avoid double counting).
func emitManagerLogs(ch chan<- prometheus.Metric, node string, body []byte) {
	var ml managerLogsSummary
	if json.Unmarshal(body, &ml) != nil {
		return
	}
	if ml.Error != nil && *ml.Error != 0 {
		return
	}
	// Dedup by (tag, level): the same tag in two array elements would otherwise
	// emit a duplicate (desc, labelvalues) series and fail Gather (500).
	type key struct{ tag, level string }
	sums := map[key]float64{}
	for _, item := range ml.Data.AffectedItems {
		for tag, levels := range item {
			for level, count := range levels {
				if strings.EqualFold(level, "all") || count < 0 {
					continue
				}
				sums[key{tag, level}] += count
			}
		}
	}
	for k, count := range sums {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerLogs, prometheus.CounterValue, count, node, k.tag, k.level)
	}
}

type managerInfo struct {
	Error *int64 `json:"error"`
	Data  struct {
		AffectedItems []struct {
			Version   *string         `json:"version"`
			Type      *string         `json:"type"`
			MaxAgents json.RawMessage `json:"max_agents"`
		} `json:"affected_items"`
	} `json:"data"`
}

// emitManagerInfo emits manager_info{node,type,version} (+ max_agents) from a /…/info body.
func emitManagerInfo(ch chan<- prometheus.Metric, node string, body []byte) {
	var mi managerInfo
	if json.Unmarshal(body, &mi) != nil || (mi.Error != nil && *mi.Error != 0) || len(mi.Data.AffectedItems) == 0 {
		return
	}
	it := mi.Data.AffectedItems[0]
	ch <- prometheus.MustNewConstMetric(metrics.ManagerInfo, prometheus.GaugeValue, 1, node, strOr(it.Type), strOr(it.Version))
	// max_agents may be a JSON number or a string like "unlimited"; emit only when numeric.
	if n, ok := lenientNumber(it.MaxAgents); ok && n >= 0 {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerMaxAgents, prometheus.GaugeValue, n, node)
	}
}

type managerValidation struct {
	Error *int64 `json:"error"`
	Data  struct {
		TotalFailedItems *int64 `json:"total_failed_items"`
		AffectedItems    []struct {
			Name   *string `json:"name"`
			Status *string `json:"status"`
		} `json:"affected_items"`
	} `json:"data"`
}

// emitConfigValid emits config_valid{node} for a single node from
// /manager/configuration/validation (standalone). The label is the configured
// node — the body validates the one local manager.
func emitConfigValid(ch chan<- prometheus.Metric, node string, body []byte) {
	var mv managerValidation
	if json.Unmarshal(body, &mv) != nil || (mv.Error != nil && *mv.Error != 0) {
		return
	}
	valid := 1.0
	if mv.Data.TotalFailedItems != nil && *mv.Data.TotalFailedItems > 0 {
		valid = 0
	}
	for _, it := range mv.Data.AffectedItems {
		if it.Status != nil && !strings.EqualFold(*it.Status, "OK") {
			valid = 0
		}
	}
	ch <- prometheus.MustNewConstMetric(metrics.ManagerConfigValid, prometheus.GaugeValue, valid, node)
}

// emitClusterConfigValid emits config_valid{node} for every node from
// /cluster/configuration/validation — a single call that validates the whole
// cluster, with one affected_item (name + status) per node.
func emitClusterConfigValid(ch chan<- prometheus.Metric, body []byte) {
	var mv managerValidation
	if json.Unmarshal(body, &mv) != nil || (mv.Error != nil && *mv.Error != 0) {
		return
	}
	seen := make(map[string]struct{})
	for _, it := range mv.Data.AffectedItems {
		if it.Name == nil || *it.Name == "" {
			continue
		}
		if _, dup := seen[*it.Name]; dup {
			continue // a repeated node name would emit a duplicate series and fail registry.Gather
		}
		seen[*it.Name] = struct{}{}
		valid := 1.0
		if it.Status != nil && !strings.EqualFold(*it.Status, "OK") {
			valid = 0
		}
		ch <- prometheus.MustNewConstMetric(metrics.ManagerConfigValid, prometheus.GaugeValue, valid, *it.Name)
	}
}

type managerStats struct {
	Error *int64 `json:"error"`
	Data  struct {
		AffectedItems []struct {
			TotalAlerts *float64 `json:"totalAlerts"`
			Events      *float64 `json:"events"`
			Syscheck    *float64 `json:"syscheck"`
			Firewall    *float64 `json:"firewall"`
		} `json:"affected_items"`
	} `json:"data"`
}

// emitManagerDailyStats emits the daily aggregate counters from a /…/stats body
// (sum of the hourly buckets). Returns nothing on the common error 1308 (totals
// file not yet generated) or a shape mismatch — only emits a field that matched.
func emitManagerDailyStats(ch chan<- prometheus.Metric, node string, body []byte) {
	var ms managerStats
	if json.Unmarshal(body, &ms) != nil || (ms.Error != nil && *ms.Error != 0) || len(ms.Data.AffectedItems) == 0 {
		return
	}
	var alerts, events, syscheck, firewall float64
	var hasAlerts, hasEvents, hasSyscheck, hasFirewall bool
	for _, h := range ms.Data.AffectedItems {
		if h.TotalAlerts != nil {
			alerts += *h.TotalAlerts
			hasAlerts = true
		}
		if h.Events != nil {
			events += *h.Events
			hasEvents = true
		}
		if h.Syscheck != nil {
			syscheck += *h.Syscheck
			hasSyscheck = true
		}
		if h.Firewall != nil {
			firewall += *h.Firewall
			hasFirewall = true
		}
	}
	if hasAlerts {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerAlerts, prometheus.CounterValue, alerts, node)
	}
	if hasEvents {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerEvents, prometheus.CounterValue, events, node)
	}
	if hasSyscheck {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerSyscheck, prometheus.CounterValue, syscheck, node)
	}
	if hasFirewall {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerFirewall, prometheus.CounterValue, firewall, node)
	}
}

type hourlyStats struct {
	Error *int64 `json:"error"`
	Data  struct {
		AffectedItems []struct {
			Averages []float64 `json:"averages"`
		} `json:"affected_items"`
	} `json:"data"`
}

// emitHourlyStats emits hourly_alerts_average{node,hour} from a /…/stats/hourly
// body: a 24-element profile of the average alerts per hour of the day.
func emitHourlyStats(ch chan<- prometheus.Metric, node string, body []byte) {
	var hs hourlyStats
	if json.Unmarshal(body, &hs) != nil || (hs.Error != nil && *hs.Error != 0) || len(hs.Data.AffectedItems) == 0 {
		return
	}
	for hour, v := range hs.Data.AffectedItems[0].Averages {
		ch <- prometheus.MustNewConstMetric(metrics.ManagerHourlyAlertsAvg, prometheus.GaugeValue, v, node, fmt.Sprintf("%02d", hour))
	}
}

type weeklyStats struct {
	Error *int64 `json:"error"`
	Data  struct {
		// Each affected_item is a single-key object: {"Mon": {"hours": [...24]}}.
		AffectedItems []map[string]struct {
			Hours []float64 `json:"hours"`
		} `json:"affected_items"`
	} `json:"data"`
}

// emitWeeklyStats emits weekly_alerts_average{node,day,hour} from a /…/stats/weekly
// body: for each weekday, a 24-element profile of the average alerts per hour.
func emitWeeklyStats(ch chan<- prometheus.Metric, node string, body []byte) {
	var ws weeklyStats
	if json.Unmarshal(body, &ws) != nil || (ws.Error != nil && *ws.Error != 0) {
		return
	}
	seen := make(map[string]struct{})
	for _, item := range ws.Data.AffectedItems {
		for day, dd := range item {
			if _, dup := seen[day]; dup {
				continue // a repeated weekday would emit duplicate series and fail registry.Gather
			}
			seen[day] = struct{}{}
			for hour, v := range dd.Hours {
				ch <- prometheus.MustNewConstMetric(metrics.ManagerWeeklyAlertsAvg, prometheus.GaugeValue, v, node, day, fmt.Sprintf("%02d", hour))
			}
		}
	}
}

// lenientNumber parses a JSON value that may be a number or a numeric string.
func lenientNumber(raw json.RawMessage) (float64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, false
	}
	s = strings.Trim(s, `"`)
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}
