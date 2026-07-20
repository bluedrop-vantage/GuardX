package detector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/guardx/gateway/internal/policy"
)

// Dispatcher runs guards in parallel and returns per-guard outcomes.
type Dispatcher struct {
	Registry *Registry
	Default  DispatchDefaults
}

// DispatchDefaults captures gateway-level knobs; policy-level values override.
type DispatchDefaults struct {
	Timeout     time.Duration
	FailMode    string // "open" | "closed"
}

func NewDispatcher(r *Registry) *Dispatcher {
	return &Dispatcher{
		Registry: r,
		Default:  DispatchDefaults{Timeout: 400 * time.Millisecond, FailMode: "closed"},
	}
}

// Run evaluates every guard in `guards` whose direction matches `direction`
// against `text`. Guards are fan-out concurrently; the whole call is bounded
// by `budget`.
func (d *Dispatcher) Run(
	ctx context.Context,
	requestID, app, direction, text string,
	p *policy.Resolved,
	budget time.Duration,
) []GuardOutcome {
	if budget <= 0 {
		budget = d.Default.Timeout
	}
	if p.TimeoutMs > 0 && time.Duration(p.TimeoutMs)*time.Millisecond < budget {
		budget = time.Duration(p.TimeoutMs) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var toRun []policy.Guard
	for _, g := range p.Guards {
		if guardMatchesDirection(g, direction) {
			toRun = append(toRun, g)
		}
	}
	if len(toRun) == 0 {
		return nil
	}

	out := make([]GuardOutcome, len(toRun))
	var wg sync.WaitGroup
	for i := range toRun {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = d.runOne(ctx, requestID, app, direction, text, toRun[i], p)
		}()
	}
	wg.Wait()
	return out
}

func (d *Dispatcher) runOne(
	ctx context.Context,
	requestID, app, direction, text string,
	g policy.Guard,
	p *policy.Resolved,
) GuardOutcome {
	start := time.Now()
	oc := GuardOutcome{Guard: g}

	backend := d.Registry.Get(g.Detector)
	if backend == nil {
		oc.Err = fmt.Errorf("detector %q not registered", g.Detector)
		oc.Result = d.errorResultForFailMode(g, p)
		oc.Elapsed = time.Since(start)
		return oc
	}

	req := Request{
		RequestID: requestID,
		Text:      text,
		Direction: direction,
		Config:    g.Config,
		App:       app,
	}
	res, err := backend.Check(ctx, req)
	oc.Result = res
	oc.Err = err

	if err != nil || res.Verdict == "ERROR" {
		oc.Result = d.errorResultForFailMode(g, p)
		if oc.Err == nil {
			oc.Err = errors.New(res.Explanation)
		}
		oc.Elapsed = time.Since(start)
		return oc
	}

	// Tier-2 escalation (spec §4.3.3):
	//   guard.config.escalation      = "<detector_id>@<version>"
	//   guard.config.escalation_floor = float in [0, threshold)
	// When the tier-1 score falls in [floor, guard.threshold) we route to the
	// escalation detector and use its verdict/spans.
	if esc, ok := escalate(g, oc.Result); ok {
		if escBackend := d.Registry.Get(esc.detector); escBackend != nil {
			escReq := req
			escReq.Config = mergedConfig(g.Config, map[string]any{"escalated_from": g.Detector})
			eres, eerr := escBackend.Check(ctx, escReq)
			if eerr == nil && eres.Verdict != "ERROR" {
				eres.Explanation = "tier-2 escalation: " + eres.Explanation
				oc.Result = eres
			}
		}
	}
	oc.Elapsed = time.Since(start)
	return oc
}

type escalationRule struct {
	detector string
	floor    float64
}

// escalate reads the guard's escalation config and returns a rule + true when
// the tier-1 score is in the escalation band.
func escalate(g policy.Guard, r Result) (escalationRule, bool) {
	det, _ := g.Config["escalation"].(string)
	if det == "" {
		return escalationRule{}, false
	}
	floor := 0.5
	if v, ok := g.Config["escalation_floor"].(float64); ok {
		floor = v
	}
	threshold := 1.0
	if v, ok := g.Threshold.(float64); ok {
		threshold = v
	}
	if r.Score >= floor && r.Score < threshold {
		return escalationRule{detector: det, floor: floor}, true
	}
	return escalationRule{}, false
}

func mergedConfig(base, extra map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// errorResultForFailMode maps a detector error into a synthetic verdict
// according to per-guard (or policy-default) fail_mode.
//
// closed = block on detector error (verdict=FAIL, on_fail applies)
// open   = pass but emit guard_error event (verdict=PASS, actions no-op)
func (d *Dispatcher) errorResultForFailMode(g policy.Guard, p *policy.Resolved) Result {
	mode := g.FailMode
	if mode == "" {
		mode = p.FailMode
	}
	if mode == "" {
		mode = d.Default.FailMode
	}
	if mode == "open" {
		return Result{Verdict: "PASS", Explanation: "detector error, fail_mode=open"}
	}
	return Result{Verdict: "FAIL", Explanation: "detector error, fail_mode=closed"}
}

func guardMatchesDirection(g policy.Guard, direction string) bool {
	for _, d := range g.Direction {
		if d == direction {
			return true
		}
	}
	return false
}

// GuardBlocks reports whether an outcome should trigger a hard-block action.
// Called after Run() so the proxy can short-circuit before mutating text.
func (o GuardOutcome) GuardBlocks() bool {
	if o.Result.Verdict != "FAIL" {
		return false
	}
	switch o.Guard.OnFail {
	case "block", "block_and_explain":
		return true
	}
	return false
}
