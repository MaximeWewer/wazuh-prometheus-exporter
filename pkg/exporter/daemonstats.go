package exporter

import (
	"encoding/json"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
)

// daemonsStats is the shared shape of /manager/daemons/stats and
// /cluster/<node>/daemons/stats: a list of daemons (wazuh-analysisd,
// wazuh-remoted, wazuh-db) each with a free-form metrics object that we decode
// per daemon. Fields are pointers/raw so absent keys simply yield no metric.
type daemonsStats struct {
	Error   *int64  `json:"error"`
	Message *string `json:"message"`
	Data    struct {
		AffectedItems []struct {
			Name    string          `json:"name"`
			Metrics json.RawMessage `json:"metrics"`
		} `json:"affected_items"`
	} `json:"data"`
}

type analysisdMetrics struct {
	Events struct {
		Received  *float64 `json:"received"`
		Processed *float64 `json:"processed"`
		Breakdown struct {
			Decoded json.RawMessage `json:"decoded_breakdown"`
			Dropped json.RawMessage `json:"dropped_breakdown"`
		} `json:"received_breakdown"`
		Written map[string]float64 `json:"written_breakdown"`
	} `json:"events"`
	Queues map[string]struct {
		Size  *float64 `json:"size"`
		Usage *float64 `json:"usage"`
	} `json:"queues"`
}

type remotedMetrics struct {
	Bytes struct {
		Received *float64 `json:"received"`
		Sent     *float64 `json:"sent"`
	} `json:"bytes"`
	TCPSessions *float64 `json:"tcp_sessions"`
	Messages    struct {
		ReceivedBreakdown struct {
			Event         *float64 `json:"event"`
			Control       *float64 `json:"control"`
			Discarded     *float64 `json:"discarded"`
			DequeuedAfter *float64 `json:"dequeued_after"`
		} `json:"received_breakdown"`
		SentBreakdown map[string]float64 `json:"sent_breakdown"`
	} `json:"messages"`
	Queues struct {
		Received struct {
			Size  *float64 `json:"size"`
			Usage *float64 `json:"usage"`
		} `json:"received"`
	} `json:"queues"`
}

type dbMetrics struct {
	Queries struct {
		Received          *float64                   `json:"received"`
		ReceivedBreakdown map[string]json.RawMessage `json:"received_breakdown"`
	} `json:"queries"`
}

// emitDaemonsStats decodes a daemons/stats body and emits the analysisd, remoted
// and wazuh-db metrics for the given node. Returns an error only on a transport
// failure or a non-zero Wazuh error envelope (so the caller can record it);
// individual daemon/field absences are tolerated.
func emitDaemonsStats(ch chan<- prometheus.Metric, node string, body []byte) error {
	var ds daemonsStats
	if err := json.Unmarshal(body, &ds); err != nil {
		return err
	}
	if err := envelopeError(ds.Error, ds.Message, "daemons stats"); err != nil {
		return err
	}
	for _, it := range ds.Data.AffectedItems {
		switch it.Name {
		case "wazuh-analysisd":
			emitAnalysisd(ch, node, it.Metrics)
		case "wazuh-remoted":
			emitRemoted(ch, node, it.Metrics)
		case "wazuh-db":
			emitDB(ch, node, it.Metrics)
		}
	}
	return nil
}

func ctr(ch chan<- prometheus.Metric, d *prometheus.Desc, v *float64, lv ...string) {
	if v != nil && *v >= 0 {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, *v, lv...)
	}
}

func emitAnalysisd(ch chan<- prometheus.Metric, node string, raw []byte) {
	var m analysisdMetrics
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	ctr(ch, metrics.AnalysisdEventsReceived, m.Events.Received, node)
	ctr(ch, metrics.AnalysisdEventsProcessed, m.Events.Processed, node)
	if d, ok := sumBreakdown(m.Events.Breakdown.Dropped); ok {
		ch <- prometheus.MustNewConstMetric(metrics.AnalysisdEventsDropped, prometheus.CounterValue, d, node)
	}
	if v, ok := m.Events.Written["alerts"]; ok {
		ch <- prometheus.MustNewConstMetric(metrics.AnalysisdAlertsWritten, prometheus.CounterValue, v, node)
	}
	if v, ok := m.Events.Written["firewall"]; ok {
		ch <- prometheus.MustNewConstMetric(metrics.AnalysisdFirewallWritten, prometheus.CounterValue, v, node)
	}
	if v, ok := m.Events.Written["fts"]; ok {
		ch <- prometheus.MustNewConstMetric(metrics.AnalysisdFTSWritten, prometheus.CounterValue, v, node)
	}
	for q, v := range m.Queues {
		if v.Usage != nil && *v.Usage >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.AnalysisdQueueSize, prometheus.GaugeValue, *v.Usage, node, q)
		}
		if v.Size != nil && *v.Size >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.AnalysisdQueueCapacity, prometheus.GaugeValue, *v.Size, node, q)
		}
		if v.Usage != nil && v.Size != nil && *v.Size > 0 {
			r := *v.Usage / *v.Size
			if r < 0 {
				r = 0
			} else if r > 1 {
				r = 1
			}
			ch <- prometheus.MustNewConstMetric(metrics.AnalysisdQueueUsageRatio, prometheus.GaugeValue, r, node, q)
		}
	}
	// Per-module decode counters: flatten the nested decoded_breakdown tree.
	for module, v := range flattenBreakdown(m.Events.Breakdown.Decoded) {
		ch <- prometheus.MustNewConstMetric(metrics.AnalysisdEventsDecoded, prometheus.CounterValue, v, node, module)
	}
}

func emitRemoted(ch chan<- prometheus.Metric, node string, raw []byte) {
	var m remotedMetrics
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	if m.TCPSessions != nil {
		ch <- prometheus.MustNewConstMetric(metrics.RemotedTCPSessions, prometheus.GaugeValue, *m.TCPSessions, node)
	}
	ctr(ch, metrics.RemotedRecvBytes, m.Bytes.Received, node)
	ctr(ch, metrics.RemotedSentBytes, m.Bytes.Sent, node)
	ctr(ch, metrics.RemotedEvtCount, m.Messages.ReceivedBreakdown.Event, node)
	ctr(ch, metrics.RemotedCtrlMsgCount, m.Messages.ReceivedBreakdown.Control, node)
	ctr(ch, metrics.RemotedDiscardedCount, m.Messages.ReceivedBreakdown.Discarded, node)
	ctr(ch, metrics.RemotedDequeuedAfterClose, m.Messages.ReceivedBreakdown.DequeuedAfter, node)
	if len(m.Messages.SentBreakdown) > 0 {
		var sent float64
		for _, v := range m.Messages.SentBreakdown {
			sent += v
		}
		ch <- prometheus.MustNewConstMetric(metrics.RemotedMsgSent, prometheus.CounterValue, sent, node)
	}
	if m.Queues.Received.Usage != nil {
		ch <- prometheus.MustNewConstMetric(metrics.RemotedQueueSize, prometheus.GaugeValue, *m.Queues.Received.Usage, node)
	}
	if m.Queues.Received.Size != nil {
		ch <- prometheus.MustNewConstMetric(metrics.RemotedQueueCapacity, prometheus.GaugeValue, *m.Queues.Received.Size, node)
	}
}

func emitDB(ch chan<- prometheus.Metric, node string, raw []byte) {
	var m dbMetrics
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	ctr(ch, metrics.DBQueriesReceived, m.Queries.Received, node)
	for category, rm := range m.Queries.ReceivedBreakdown {
		// Each category may be a number or an object with a "queries" count.
		if n := numberOrField(rm, "queries"); n != nil && *n >= 0 {
			ch <- prometheus.MustNewConstMetric(metrics.DBQueriesBreakdown, prometheus.CounterValue, *n, node, category)
		}
	}
}

// sumBreakdown sums every numeric leaf of a nested breakdown object. The bool is
// false when the object has no numeric leaves (so the caller can skip emitting,
// rather than relying on a sentinel value).
func sumBreakdown(raw []byte) (float64, bool) {
	leaves := flattenBreakdown(raw)
	if len(leaves) == 0 {
		return 0, false
	}
	var total float64
	for _, v := range leaves {
		total += v
	}
	return total, true
}

// maxBreakdownDepth caps flattenBreakdown recursion. Real Wazuh decode trees are
// 2-3 levels deep; this guards against a pathologically deep API response
// exhausting the goroutine stack.
const maxBreakdownDepth = 16

// flattenBreakdown walks a nested {key: number | {…}} tree and returns a flat
// map of module->count. Nested object keys are joined with "_", and a trailing
// "_breakdown" on a key is stripped (e.g. modules_breakdown.syscheck → syscheck;
// modules_breakdown.logcollector_breakdown.eventchannel → logcollector_eventchannel).
func flattenBreakdown(raw []byte) map[string]float64 {
	out := map[string]float64{}
	var tree map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &tree) != nil {
		return out
	}
	var walk func(prefix string, node map[string]json.RawMessage, depth int)
	walk = func(prefix string, node map[string]json.RawMessage, depth int) {
		if depth > maxBreakdownDepth {
			return
		}
		for k, v := range node {
			key := strings.TrimSuffix(k, "_breakdown")
			var f float64
			if json.Unmarshal(v, &f) == nil {
				name := key
				if prefix != "" {
					name = prefix + "_" + key
				}
				out[name] = f
				continue
			}
			var child map[string]json.RawMessage
			if json.Unmarshal(v, &child) == nil {
				p := key
				// Don't prefix with generic container names that add no signal.
				if key == "modules" || key == "integrations" || prefix == "modules" || prefix == "integrations" {
					p = prefix
				}
				walk(p, child, depth+1)
			}
		}
	}
	walk("", tree, 0)
	return out
}

// numberOrField returns raw as a float, or raw[field] if raw is an object. The
// object is decoded leniently (map of raw messages) so a non-numeric sibling
// field does not cause the whole object — and the wanted field — to be dropped.
func numberOrField(raw json.RawMessage, field string) *float64 {
	var f float64
	if json.Unmarshal(raw, &f) == nil {
		return &f
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		if v, ok := obj[field]; ok {
			var n float64
			if json.Unmarshal(v, &n) == nil {
				return &n
			}
		}
	}
	return nil
}
