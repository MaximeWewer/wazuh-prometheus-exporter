// Package exporter hosts the scrape orchestrator (the prometheus.Collector that
// serializes scrapes, bounds collector concurrency, recovers panics, drives the
// wazuh_up metric and the exporter self-metrics) plus the per-domain collectors.
package exporter

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/metrics"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

const defaultMaxConcurrency = 4

// Collector is a domain collector emitting metrics for one Wazuh subsystem.
//
// Contract:
//   - Return an error on failure rather than panicking (the orchestrator does
//     recover panics, but they are counted as errors).
//   - Each collector MUST emit a set of descriptor+label tuples disjoint from
//     every other registered collector — two collectors emitting the same
//     metric series make registry.Gather fail the whole /metrics scrape.
//   - Perform all fallible reads BEFORE sending any metric to ch, so that a
//     returned error omits all of the collector's series (no partial emission).
type Collector interface {
	Name() string
	Collect(ctx context.Context, ch chan<- prometheus.Metric) error
}

// Exporter orchestrates domain collectors and implements prometheus.Collector.
type Exporter struct {
	log            zerolog.Logger
	mon            *monitoring.Metrics
	collectors     []Collector
	scrapeTimeout  time.Duration
	maxConcurrency int
	startedAt      time.Time
	startupGrace   time.Duration // quiet-startup window; 0 disables

	collectMu sync.Mutex  // serializes whole scrapes
	ready     atomic.Bool // sticky: set once a collection first succeeds
}

// New builds an Exporter over the given domain collectors.
func New(log zerolog.Logger, mon *monitoring.Metrics, scrapeTimeout time.Duration, collectors ...Collector) *Exporter {
	e := &Exporter{
		log:            log,
		mon:            mon,
		collectors:     collectors,
		scrapeTimeout:  scrapeTimeout,
		maxConcurrency: defaultMaxConcurrency,
		startedAt:      time.Now(),
	}
	if len(collectors) == 0 {
		// Self-metrics-only mode (no API credentials): nothing to reach, so the
		// exporter is ready as soon as it is serving.
		e.ready.Store(true)
	}
	return e
}

// SetStartupGrace sets a quiet-startup window: until the first successful
// collection (or until the window elapses), collection failures are logged at
// warn ("waiting for Wazuh API") instead of error, so a slow-to-boot Wazuh
// doesn't look like an outage. Metrics (collector_errors_total, wazuh_up=0) are
// unaffected. 0 disables it (failures log at error from the start).
func (e *Exporter) SetStartupGrace(d time.Duration) { e.startupGrace = d }

// inStartupGrace reports whether collection failures should be logged calmly:
// the grace window is configured, no collection has succeeded yet, and the window
// has not elapsed.
func (e *Exporter) inStartupGrace() bool {
	return e.startupGrace > 0 && !e.ready.Load() && time.Since(e.startedAt) < e.startupGrace
}

// Ready reports readiness: true once a collection has succeeded at least once
// (sticky — it does not flip back on a later transient Wazuh outage, so it never
// suppresses the wazuh_up=0 signal). Self-metrics-only mode is ready immediately.
func (e *Exporter) Ready() bool { return e.ready.Load() }

// CollectOnce runs one collection, discarding the metrics. It lets a caller drive
// readiness / self-metrics without waiting for a Prometheus scrape.
func (e *Exporter) CollectOnce() {
	ch := make(chan prometheus.Metric, 64)
	done := make(chan struct{})
	go func() {
		for range ch { //nolint:revive // drain
		}
		close(done)
	}()
	e.Collect(ch)
	close(ch)
	<-done
}

// Describe is a no-op: descriptors are emitted dynamically via MustNewConstMetric
// in Collect (the exporter is an unchecked collector).
func (e *Exporter) Describe(chan<- *prometheus.Desc) {}

// Collect runs all domain collectors under a serialized, bounded, panic-safe
// scrape, records self-metrics, and emits wazuh_up.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.collectMu.Lock()
	defer e.collectMu.Unlock()

	start := time.Now()

	ctx := context.Background()
	if e.scrapeTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.scrapeTimeout)
		defer cancel()
	}

	var (
		wg         sync.WaitGroup
		sem        = make(chan struct{}, e.maxConcurrency)
		mu         sync.Mutex
		anySuccess bool
	)

	for _, c := range e.collectors {
		wg.Add(1)
		sem <- struct{}{}
		go func(c Collector) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					e.log.Error().Str("component", "exporter").Str("collector", c.Name()).
						Interface("panic", r).Msg("collector panicked")
					e.mon.CollectorErrors.WithLabelValues(c.Name(), "panic").Inc()
				}
			}()

			if err := c.Collect(ctx, ch); err != nil {
				ev, msg := e.log.Error(), "collector failed"
				if e.inStartupGrace() {
					ev, msg = e.log.Warn(), "collector failed during startup grace (waiting for Wazuh API)"
				}
				ev.Str("component", "exporter").Str("collector", c.Name()).Err(err).Msg(msg)
				e.mon.CollectorErrors.WithLabelValues(c.Name(), "collect").Inc()
				return
			}
			e.mon.CollectorSuccess.WithLabelValues(c.Name()).Inc()
			mu.Lock()
			anySuccess = true
			mu.Unlock()
		}(c)
	}
	wg.Wait()

	e.mon.ScrapeDuration.Observe(time.Since(start).Seconds())

	// up=1 only if at least one collector succeeded. With no collectors configured
	// (no API credentials) the exporter is not collecting Wazuh, so up=0 — a
	// credential-less or misconfigured exporter must not look healthy.
	up := 0.0
	if anySuccess {
		up = 1
		e.ready.Store(true) // sticky readiness: first successful collection
	}
	ch <- prometheus.MustNewConstMetric(metrics.UpDesc, prometheus.GaugeValue, up)
}
