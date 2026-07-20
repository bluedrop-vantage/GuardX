// Package metrics exposes a small Prometheus-text-format /metrics endpoint
// backed by lock-free atomic counters and lightweight histograms.
//
// Deliberately no third-party client: gateway stays stdlib-only, and the
// exposition format is stable and simple. If prometheus/client_golang lands
// later, migrate — the metric names and label sets here match theirs.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// -- Counter ---------------------------------------------------------------

type counter struct {
	value  atomic.Int64
	labels map[string]string
}

// Registry holds every counter/histogram/gauge and renders /metrics output.
type Registry struct {
	mu     sync.Mutex
	family map[string]*family
}

type family struct {
	name    string
	help    string
	kind    string // "counter" | "histogram" | "gauge"
	counters map[string]*counter
	gauges  map[string]*gauge
	hists   map[string]*histogram
}

func NewRegistry() *Registry {
	return &Registry{family: map[string]*family{}}
}

func (r *Registry) fam(name, help, kind string) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.family[name]
	if f == nil {
		f = &family{
			name: name, help: help, kind: kind,
			counters: map[string]*counter{},
			gauges:   map[string]*gauge{},
			hists:    map[string]*histogram{},
		}
		r.family[name] = f
	}
	return f
}

// Counter returns a monotonic counter with the given labels.
func (r *Registry) Counter(name, help string, labels map[string]string) *counter {
	f := r.fam(name, help, "counter")
	k := labelKey(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	c := f.counters[k]
	if c == nil {
		c = &counter{labels: labels}
		f.counters[k] = c
	}
	return c
}

func (c *counter) Inc()          { c.value.Add(1) }
func (c *counter) Add(n int64)   { c.value.Add(n) }

// -- Gauge -----------------------------------------------------------------

type gauge struct {
	value  atomic.Int64
	labels map[string]string
}

func (r *Registry) Gauge(name, help string, labels map[string]string) *gauge {
	f := r.fam(name, help, "gauge")
	k := labelKey(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	g := f.gauges[k]
	if g == nil {
		g = &gauge{labels: labels}
		f.gauges[k] = g
	}
	return g
}

func (g *gauge) Set(v int64) { g.value.Store(v) }
func (g *gauge) Inc()        { g.value.Add(1) }
func (g *gauge) Dec()        { g.value.Add(-1) }

// -- Histogram (fixed buckets) --------------------------------------------

// Default latency buckets in milliseconds, aligned with spec §4.1 targets.
var DefaultLatencyBuckets = []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

type histogram struct {
	labels  map[string]string
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Int64 // milliseconds; stored as int64 for lock-free updates
	count   atomic.Int64
}

func (r *Registry) Histogram(name, help string, buckets []float64, labels map[string]string) *histogram {
	if buckets == nil {
		buckets = DefaultLatencyBuckets
	}
	f := r.fam(name, help, "histogram")
	k := labelKey(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	h := f.hists[k]
	if h == nil {
		h = &histogram{
			labels:  labels,
			buckets: append([]float64(nil), buckets...),
			counts:  make([]atomic.Int64, len(buckets)),
		}
		f.hists[k] = h
	}
	return h
}

// Observe records a sample in milliseconds.
func (h *histogram) Observe(ms int64) {
	h.count.Add(1)
	h.sum.Add(ms)
	v := float64(ms)
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i].Add(1)
			break
		}
	}
}

// -- Render ---------------------------------------------------------------

func (r *Registry) Render(w io.Writer) {
	r.mu.Lock()
	names := make([]string, 0, len(r.family))
	for n := range r.family {
		names = append(names, n)
	}
	sort.Strings(names)
	r.mu.Unlock()

	for _, n := range names {
		f := r.family[n]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", f.name, f.help, f.name, f.kind)
		switch f.kind {
		case "counter":
			for _, c := range sortedCounters(f.counters) {
				fmt.Fprintf(w, "%s%s %d\n", f.name, renderLabels(c.labels), c.value.Load())
			}
		case "gauge":
			for _, g := range sortedGauges(f.gauges) {
				fmt.Fprintf(w, "%s%s %d\n", f.name, renderLabels(g.labels), g.value.Load())
			}
		case "histogram":
			for _, h := range sortedHistograms(f.hists) {
				var cum int64
				for i, b := range h.buckets {
					cum += h.counts[i].Load()
					lbls := mergeLabels(h.labels, map[string]string{"le": fmt.Sprintf("%g", b)})
					fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, renderLabels(lbls), cum)
				}
				lbls := mergeLabels(h.labels, map[string]string{"le": "+Inf"})
				fmt.Fprintf(w, "%s_bucket%s %d\n", f.name, renderLabels(lbls), h.count.Load())
				fmt.Fprintf(w, "%s_sum%s %d\n", f.name, renderLabels(h.labels), h.sum.Load())
				fmt.Fprintf(w, "%s_count%s %d\n", f.name, renderLabels(h.labels), h.count.Load())
			}
		}
	}
}

// -- Handler --------------------------------------------------------------

// Handler returns an http.Handler exposing /metrics in Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		r.Render(w)
	})
}

// -- helpers --------------------------------------------------------------

func labelKey(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(m[k])
		sb.WriteByte(0)
	}
	return sb.String()
}

func renderLabels(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escape(m[k])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func mergeLabels(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

// Sorted iterators for stable output.
func sortedCounters(m map[string]*counter) []*counter {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := make([]*counter, 0, len(ks))
	for _, k := range ks {
		out = append(out, m[k])
	}
	return out
}

func sortedGauges(m map[string]*gauge) []*gauge {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := make([]*gauge, 0, len(ks))
	for _, k := range ks {
		out = append(out, m[k])
	}
	return out
}

func sortedHistograms(m map[string]*histogram) []*histogram {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	out := make([]*histogram, 0, len(ks))
	for _, k := range ks {
		out = append(out, m[k])
	}
	return out
}
