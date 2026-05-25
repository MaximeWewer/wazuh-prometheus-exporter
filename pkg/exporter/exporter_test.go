package exporter

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/rs/zerolog"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

func TestExporter_StartupGraceLogLevel(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	var buf bytes.Buffer
	lg := zerolog.New(&buf)

	// Within the grace window, a failing collector logs at warn ("waiting"), not error.
	e := New(lg, mon, time.Second, fakeCollector{name: "x", err: errors.New("down")})
	e.SetStartupGrace(time.Minute)
	e.CollectOnce()
	if out := buf.String(); !strings.Contains(out, `"level":"warn"`) ||
		!strings.Contains(out, "waiting for Wazuh API") || strings.Contains(out, `"level":"error"`) {
		t.Errorf("in-grace failure should log warn, not error; got: %s", out)
	}

	// With no grace configured, a failing collector logs at error.
	buf.Reset()
	e2 := New(lg, mon, time.Second, fakeCollector{name: "y", err: errors.New("down")})
	e2.CollectOnce()
	if out := buf.String(); !strings.Contains(out, `"level":"error"`) {
		t.Errorf("without grace, failure should log error; got: %s", out)
	}
}

type fakeCollector struct {
	name   string
	err    error
	panics bool
}

func (f fakeCollector) Name() string { return f.name }

func (f fakeCollector) Collect(_ context.Context, _ chan<- prometheus.Metric) error {
	if f.panics {
		panic("boom")
	}
	return f.err
}

func gatherUp(t *testing.T, e *Exporter) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := reg.Register(e); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "wazuh_up" {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatal("wazuh_up not emitted")
	return -1
}

func TestExporter_UpOneOnSuccess(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, fakeCollector{name: "ok"})
	if up := gatherUp(t, e); up != 1 {
		t.Fatalf("wazuh_up = %v, want 1", up)
	}
	if got := testutil.ToFloat64(mon.CollectorSuccess.WithLabelValues("ok")); got != 1 {
		t.Errorf("collector_success_total{ok} = %v, want 1", got)
	}
}

func TestExporter_UpZeroWhenAllFail(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, fakeCollector{name: "bad", err: errors.New("nope")})
	if up := gatherUp(t, e); up != 0 {
		t.Fatalf("wazuh_up = %v, want 0", up)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("bad", "collect")); got != 1 {
		t.Errorf("collector_errors_total{bad,collect} = %v, want 1", got)
	}
}

func TestExporter_PanicIsRecoveredAndCounted(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, fakeCollector{name: "panicky", panics: true})
	if up := gatherUp(t, e); up != 0 { // panic counts as failure
		t.Fatalf("wazuh_up = %v, want 0", up)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("panicky", "panic")); got != 1 {
		t.Errorf("collector_errors_total{panicky,panic} = %v, want 1", got)
	}
}

func TestExporter_PartialSuccessKeepsUpOne(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second,
		fakeCollector{name: "ok"},
		fakeCollector{name: "bad", err: errors.New("x")},
	)
	if up := gatherUp(t, e); up != 1 {
		t.Fatalf("wazuh_up = %v, want 1 (one collector succeeded)", up)
	}
}

func TestExporter_Readiness(t *testing.T) {
	mon := monitoring.New("test", time.Now())

	// Self-metrics-only mode (no collectors): ready immediately.
	if e := New(logger.New("error"), mon, time.Second); !e.Ready() {
		t.Error("no-collector exporter should be ready at construction")
	}

	// A failing collector: not ready before, still not ready after a failed scrape.
	ef := New(logger.New("error"), mon, time.Second, fakeCollector{name: "x", err: errors.New("down")})
	if ef.Ready() {
		t.Error("exporter with a collector should not be ready before any success")
	}
	ef.CollectOnce()
	if ef.Ready() {
		t.Error("readiness must stay false after a failed collection")
	}

	// A succeeding collector flips readiness; it then stays ready (sticky) even if
	// a later collection fails.
	flaky := &flakyCollector{}
	es := New(logger.New("error"), mon, time.Second, flaky)
	es.CollectOnce()
	if !es.Ready() {
		t.Fatal("readiness should flip true after first success")
	}
	flaky.fail = true
	es.CollectOnce()
	if !es.Ready() {
		t.Error("readiness must be sticky (stay true) across a later failure")
	}
}

type flakyCollector struct{ fail bool }

func (f *flakyCollector) Name() string { return "flaky" }
func (f *flakyCollector) Collect(_ context.Context, _ chan<- prometheus.Metric) error {
	if f.fail {
		return errors.New("down")
	}
	return nil
}

func TestExporter_NoCollectorsUpZero(t *testing.T) {
	// No collectors configured (e.g. no API credentials) → the exporter is not
	// collecting Wazuh, so wazuh_up must be 0, not a misleading 1.
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second)
	if up := gatherUp(t, e); up != 0 {
		t.Fatalf("wazuh_up = %v, want 0 with no collectors", up)
	}
}
