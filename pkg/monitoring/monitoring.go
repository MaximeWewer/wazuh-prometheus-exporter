// Package monitoring exposes the exporter's own self-metrics in the
// wazuh_exporter namespace (build info, scrape latency, per-collector counters,
// uptime) plus Go runtime and process metrics, on a dedicated registry served
// at /internal/metrics.
package monitoring

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
)

// Metrics holds the exporter's own instruments and the registry they live on.
// They are exposed for domain collectors (Epic 2) to observe. The ScrapeDuration
// histogram exports at zero from registration; the counter vecs carry no series
// until a collector first observes a label set.
type Metrics struct {
	reg *prometheus.Registry

	ScrapeDuration   prometheus.Histogram
	CollectorSuccess *prometheus.CounterVec
	CollectorErrors  *prometheus.CounterVec
	CacheHits        prometheus.Counter
	CacheMisses      prometheus.Counter
}

// New builds the self-metrics registry: build_info, uptime, scrape-duration
// histogram, per-collector counters, plus Go runtime and process collectors.
func New(version string, started time.Time) *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		reg: reg,
		ScrapeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: metrics.ExporterNamespace,
			Name:      "scrape_duration_seconds",
			Help:      "Duration of a Wazuh collector scrape, in seconds.",
			// Network-bound scrapes can run long; extend well past DefBuckets' 10s.
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60},
		}),
		CollectorSuccess: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.ExporterNamespace,
			Name:      "collector_success_total",
			Help:      "Total successful collections, per collector.",
		}, []string{"collector"}),
		CollectorErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.ExporterNamespace,
			Name:      "collector_errors_total",
			Help:      "Total collection errors, per collector and error type.",
		}, []string{"collector", "error_type"}),
		CacheHits: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.ExporterNamespace,
			Name:      "cache_hits_total",
			Help:      "Total Wazuh API response cache hits.",
		}),
		CacheMisses: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.ExporterNamespace,
			Name:      "cache_misses_total",
			Help:      "Total Wazuh API response cache misses.",
		}),
	}

	uptime := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metrics.ExporterNamespace,
		Name:      "uptime_seconds",
		Help:      "Seconds since the exporter started.",
	}, func() float64 {
		if d := time.Since(started); d > 0 {
			return d.Seconds()
		}
		return 0
	})

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfoCollector{version: version},
		uptime,
		m.ScrapeDuration,
		m.CollectorSuccess,
		m.CollectorErrors,
		m.CacheHits,
		m.CacheMisses,
	)

	return m
}

// Registry returns the self-metrics registry, served at /internal/metrics.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// RegisterCircuitBreakerState registers wazuh_exporter_circuit_breaker_state, a
// gauge whose value is read from read() at scrape time (0 closed, 1 half-open,
// 2 open). Call once with the live breaker's state accessor.
func (m *Metrics) RegisterCircuitBreakerState(read func() float64) {
	m.reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: metrics.ExporterNamespace,
		Name:      "circuit_breaker_state",
		Help:      "Wazuh API circuit breaker state (0 closed, 1 half-open, 2 open).",
	}, read))
}

// buildInfoCollector emits metrics.BuildInfoDesc as a constant 1 labelled by version.
type buildInfoCollector struct{ version string }

func (c buildInfoCollector) Describe(ch chan<- *prometheus.Desc) { ch <- metrics.BuildInfoDesc }

func (c buildInfoCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(metrics.BuildInfoDesc, prometheus.GaugeValue, 1, c.version)
}
