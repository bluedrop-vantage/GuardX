package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestCounter_IncrementsAndRenders(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("guardx_test_total", "test counter",
		map[string]string{"tenant": "acme", "verdict": "PASS"})
	c.Inc()
	c.Add(4)

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()
	if !strings.Contains(out, `guardx_test_total{tenant="acme",verdict="PASS"} 5`) {
		t.Fatalf("unexpected render:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE guardx_test_total counter") {
		t.Fatalf("missing TYPE line:\n%s", out)
	}
}

func TestHistogram_BucketsAndSum(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("guardx_lat_ms", "latency", []float64{10, 50, 100},
		map[string]string{"phase": "output"})
	h.Observe(5)   // → 10 bucket
	h.Observe(30)  // → 50
	h.Observe(80)  // → 100
	h.Observe(200) // → +Inf only

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()

	// Cumulative: bucket 10 = 1, bucket 50 = 2, bucket 100 = 3, +Inf = 4.
	for _, want := range []string{
		`guardx_lat_ms_bucket{le="10",phase="output"} 1`,
		`guardx_lat_ms_bucket{le="50",phase="output"} 2`,
		`guardx_lat_ms_bucket{le="100",phase="output"} 3`,
		`guardx_lat_ms_bucket{le="+Inf",phase="output"} 4`,
		`guardx_lat_ms_sum{phase="output"} 315`,
		`guardx_lat_ms_count{phase="output"} 4`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestGauge_SetAndRender(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("guardx_bundle_seq", "current bundle",
		map[string]string{"tenant": "acme", "env": "prod"})
	g.Set(42)

	var buf bytes.Buffer
	r.Render(&buf)
	if !strings.Contains(buf.String(),
		`guardx_bundle_seq{env="prod",tenant="acme"} 42`) {
		t.Fatalf("unexpected: %s", buf.String())
	}
}

func TestLabelEscaping(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("guardx_x", "x", map[string]string{"note": `has "quote" and \back`})
	c.Inc()
	var buf bytes.Buffer
	r.Render(&buf)
	if !strings.Contains(buf.String(), `note="has \"quote\" and \\back"`) {
		t.Fatalf("bad escape: %s", buf.String())
	}
}
