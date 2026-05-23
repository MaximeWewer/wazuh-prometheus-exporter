package monitoring

import (
	"testing"
	"time"
)

func TestNew_RegistersSelfMetrics(t *testing.T) {
	m := New("1.0.0-test", time.Now())
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	present := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		present[mf.GetName()] = true
	}

	// Always-present families (the empty counter vecs only appear once a series
	// is observed, so they are not asserted here).
	for _, name := range []string{
		"wazuh_exporter_build_info",
		"wazuh_exporter_uptime_seconds",
		"wazuh_exporter_scrape_duration_seconds",
		"go_goroutines",
	} {
		if !present[name] {
			t.Errorf("self registry missing metric family %q", name)
		}
	}
}

func TestNew_BuildInfoHasVersionLabel(t *testing.T) {
	m := New("9.9.9-test", time.Now())
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "wazuh_exporter_build_info" {
			continue
		}
		metric := mf.GetMetric()
		if len(metric) != 1 {
			t.Fatalf("build_info has %d series, want 1", len(metric))
		}
		for _, l := range metric[0].GetLabel() {
			if l.GetName() == "version" {
				if l.GetValue() != "9.9.9-test" {
					t.Fatalf("build_info version = %q, want 9.9.9-test", l.GetValue())
				}
				if metric[0].GetGauge().GetValue() != 1 {
					t.Fatalf("build_info value = %v, want 1", metric[0].GetGauge().GetValue())
				}
				return
			}
		}
		t.Fatal("build_info missing 'version' label")
	}
	t.Fatal("wazuh_exporter_build_info family not found")
}
