// Package gwmetrics is the domain-specific metrics collector for the gateway.
// It sits above the primitive Registry in `internal/metrics` and knows about
// guardx types (GuardOutcome, Manifest). Keeping this split means `metrics`
// stays stdlib-only and can be reused wherever a lightweight Prometheus
// exposition is useful.
package gwmetrics

import (
	"time"

	"github.com/guardx/gateway/internal/detector"
	"github.com/guardx/gateway/internal/metrics"
)

// MetricsCollector is the seam between the request path and Prometheus.
// Every path that produces evidence also calls a method here, so a metric
// exists for every guard outcome. Labels stay bounded (`tenant`, `env`,
// `app`, `scenario`, `guard_id`, `verdict`) — cardinality is under control
// as long as the tenant does not fan out apps unbounded.
type Collector struct {
	Reg    *metrics.Registry
	Tenant string
	Env    string
}

func (c *Collector)ObserveGuard(app, direction string, oc detector.GuardOutcome) {
	if c == nil || c.Reg == nil {
		return
	}
	labels := map[string]string{
		"tenant":    c.Tenant,
		"env":       c.Env,
		"app":       app,
		"scenario":  oc.Guard.Scenario,
		"guard_id":  oc.Guard.ID,
		"direction": direction,
		"verdict":   oc.Result.Verdict,
	}
	c.Reg.Counter(
		"guardx_guard_evaluations_total",
		"Guard evaluations by verdict",
		labels,
	).Inc()
	if oc.Guard.Shadow {
		c.Reg.Counter(
			"guardx_guard_shadow_total",
			"Shadow-guard evaluations",
			labels,
		).Inc()
	}
	if oc.Err != nil {
		c.Reg.Counter(
			"guardx_guard_errors_total",
			"Detector errors surfacing fail_mode",
			labels,
		).Inc()
	}
	// Latency histogram (drop verdict from labels — bucketing is the summary).
	histLabels := map[string]string{
		"tenant":   c.Tenant,
		"env":      c.Env,
		"app":      app,
		"scenario": oc.Guard.Scenario,
		"guard_id": oc.Guard.ID,
	}
	c.Reg.Histogram(
		"guardx_guard_latency_ms",
		"Per-guard latency in milliseconds",
		metrics.DefaultLatencyBuckets, histLabels,
	).Observe(oc.Elapsed.Milliseconds())
}

// ObserveAction fires once per (request, phase). "block", "redact", "mask",
// "flag", "pass" are the values the request produced after policy composition.
func (c *Collector)ObserveAction(app, direction, action string) {
	if c == nil || c.Reg == nil {
		return
	}
	c.Reg.Counter(
		"guardx_action_total",
		"Actions applied to the request/response",
		map[string]string{
			"tenant":    c.Tenant,
			"env":       c.Env,
			"app":       app,
			"direction": direction,
			"action":    action,
		},
	).Inc()
}

// ObserveBundleInstalled fires when the gateway hot-swaps to a new bundle.
func (c *Collector)ObserveBundleInstalled(seq int64, policies int, createdAt time.Time) {
	if c == nil || c.Reg == nil {
		return
	}
	c.Reg.Gauge(
		"guardx_bundle_seq",
		"Currently installed bundle sequence",
		map[string]string{"tenant": c.Tenant, "env": c.Env},
	).Set(seq)
	c.Reg.Gauge(
		"guardx_bundle_policies",
		"Number of policies in the installed bundle",
		map[string]string{"tenant": c.Tenant, "env": c.Env},
	).Set(int64(policies))
	c.Reg.Counter(
		"guardx_bundle_installed_total",
		"Cumulative bundle hot-swap count",
		map[string]string{"tenant": c.Tenant, "env": c.Env},
	).Inc()
	c.UpdateBundleAge(createdAt)
}

// UpdateBundleAge is called on a ticker so alerts can page on staleness.
func (c *Collector)UpdateBundleAge(createdAt time.Time) {
	if c == nil || c.Reg == nil {
		return
	}
	age := int64(time.Since(createdAt).Seconds())
	c.Reg.Gauge(
		"guardx_bundle_age_seconds",
		"Age of the currently installed bundle",
		map[string]string{"tenant": c.Tenant, "env": c.Env},
	).Set(age)
}
