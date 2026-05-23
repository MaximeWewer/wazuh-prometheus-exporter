package exporter

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/logger"
	"github.com/MaximeWewer/wazuh-prometheus-exporter/pkg/monitoring"
)

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
	e := New(logger.New("error"), mon, time.Second, "manager", fakeCollector{name: "ok"})
	if up := gatherUp(t, e); up != 1 {
		t.Fatalf("wazuh_up = %v, want 1", up)
	}
	if got := testutil.ToFloat64(mon.CollectorSuccess.WithLabelValues("ok")); got != 1 {
		t.Errorf("collector_success_total{ok} = %v, want 1", got)
	}
}

func TestExporter_UpZeroWhenAllFail(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, "manager", fakeCollector{name: "bad", err: errors.New("nope")})
	if up := gatherUp(t, e); up != 0 {
		t.Fatalf("wazuh_up = %v, want 0", up)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("bad", "collect")); got != 1 {
		t.Errorf("collector_errors_total{bad,collect} = %v, want 1", got)
	}
}

func TestExporter_PanicIsRecoveredAndCounted(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, "manager", fakeCollector{name: "panicky", panics: true})
	if up := gatherUp(t, e); up != 0 { // panic counts as failure
		t.Fatalf("wazuh_up = %v, want 0", up)
	}
	if got := testutil.ToFloat64(mon.CollectorErrors.WithLabelValues("panicky", "panic")); got != 1 {
		t.Errorf("collector_errors_total{panicky,panic} = %v, want 1", got)
	}
}

func TestExporter_PartialSuccessKeepsUpOne(t *testing.T) {
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, "manager",
		fakeCollector{name: "ok"},
		fakeCollector{name: "bad", err: errors.New("x")},
	)
	if up := gatherUp(t, e); up != 1 {
		t.Fatalf("wazuh_up = %v, want 1 (one collector succeeded)", up)
	}
}

func TestExporter_NoCollectorsUpZero(t *testing.T) {
	// No collectors configured (e.g. no API credentials) → the exporter is not
	// collecting Wazuh, so wazuh_up must be 0, not a misleading 1.
	mon := monitoring.New("test", time.Now())
	e := New(logger.New("error"), mon, time.Second, "manager")
	if up := gatherUp(t, e); up != 0 {
		t.Fatalf("wazuh_up = %v, want 0 with no collectors", up)
	}
}
