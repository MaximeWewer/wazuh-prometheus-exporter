package exporter

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// drain consumes a metric channel until closed, so emitters never block.
func drain(ch chan prometheus.Metric) chan struct{} {
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	return done
}

// FuzzEmitDaemonsStats feeds arbitrary bytes to the daemons/stats decoder
// (including the recursive decoded_breakdown flatten). It must never panic —
// the exporter consumes these bodies from the Wazuh API and a malformed or
// pathologically nested response must degrade gracefully, not crash a scrape.
func FuzzEmitDaemonsStats(f *testing.F) {
	f.Add([]byte(daemonsBody))
	f.Add([]byte(`{"data":{"affected_items":[{"name":"wazuh-analysisd","metrics":{"events":{"received_breakdown":{"decoded_breakdown":{"a":{"b":{"c":1}}}}}}}]}}`))
	f.Add([]byte(`{"error":4,"message":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(_ *testing.T, body []byte) {
		ch := make(chan prometheus.Metric, 256)
		done := drain(ch)
		_ = emitDaemonsStats(ch, "fuzz", body)
		close(ch)
		<-done
	})
}

// FuzzFlattenBreakdown exercises the recursive breakdown walk directly, so the
// depth cap and mixed number/object handling are stressed in isolation.
func FuzzFlattenBreakdown(f *testing.F) {
	f.Add([]byte(`{"modules_breakdown":{"syscheck":4,"logcollector_breakdown":{"eventchannel":3}}}`))
	f.Add([]byte(`{"a":{"a":{"a":{"a":1}}}}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(_ *testing.T, raw []byte) {
		_ = flattenBreakdown(raw)
		_, _ = sumBreakdown(raw)
	})
}
