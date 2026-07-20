package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/guardx/gateway/internal/detector"
	"github.com/guardx/gateway/internal/evidence"
	"github.com/guardx/gateway/internal/gwmetrics"
	"github.com/guardx/gateway/internal/policy"
)

type CheckRequest struct {
	App       string          `json:"app"`
	Direction string          `json:"direction"` // input | output
	Text      string          `json:"text,omitempty"`
	Messages  json.RawMessage `json:"messages,omitempty"`
	Context   json.RawMessage `json:"context,omitempty"`
}

type CheckResponse struct {
	Verdict   string        `json:"verdict"`   // PASS | FAIL
	Actions   []string      `json:"actions"`
	Guards    []GuardResult `json:"guards"`
	Policy    string        `json:"policy,omitempty"`
	BundleSeq int64         `json:"bundle_seq"`
	Mutated   string        `json:"mutated,omitempty"`
}

type GuardResult struct {
	ID       string  `json:"id"`
	Scenario string  `json:"scenario"`
	Detector string  `json:"detector"`
	Verdict  string  `json:"verdict"`
	Score    float64 `json:"score"`
	OnFail   string  `json:"on_fail"`
	Spans    []evidence.SpanRef `json:"spans,omitempty"`
}

type CheckHandler struct {
	Snap        *policy.Snapshot
	Emitter     evidence.Emitter
	Dispatcher  *detector.Dispatcher
	Metrics     *gwmetrics.Collector
	Tenant      string
	Environment string
}

func (h *CheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
		return
	}
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	idx := h.Snap.Load()
	if idx == nil {
		WriteInternal(w, "no policy index loaded")
		return
	}
	if req.Direction == "" {
		req.Direction = "input"
	}
	policies := idx.Resolve(req.App, h.Environment)

	res := CheckResponse{
		Verdict:   "PASS",
		Actions:   []string{},
		Guards:    []GuardResult{},
		BundleSeq: idx.BundleSeq,
	}
	requestID := r.Header.Get("X-Request-ID")
	current := req.Text
	for _, p := range policies {
		res.Policy = fmt.Sprintf("%s@%s", p.PolicyID, p.Version)
		budget := time.Duration(p.TimeoutMs) * time.Millisecond
		outcomes := h.Dispatcher.Run(r.Context(), requestID, req.App, req.Direction, current, p, budget)
		for _, oc := range outcomes {
			spans := make([]evidence.SpanRef, 0, len(oc.Result.Spans))
			for _, s := range oc.Result.Spans {
				spans = append(spans, evidence.SpanRef{
					Start: s.Start, End: s.End, Label: s.Label, Confidence: s.Confidence,
				})
			}
			res.Guards = append(res.Guards, GuardResult{
				ID: oc.Guard.ID, Scenario: oc.Guard.Scenario, Detector: oc.Guard.Detector,
				Verdict: oc.Result.Verdict, Score: oc.Result.Score,
				OnFail: oc.Guard.OnFail, Spans: spans,
			})
			h.Emitter.Emit(evidence.Event{
				Tenant: h.Tenant, App: req.App, Env: h.Environment,
				RequestID: requestID,
				Policy:    fmt.Sprintf("%s@%s", p.PolicyID, p.Version),
				BundleSeq: idx.BundleSeq,
				GuardID:   oc.Guard.ID, Scenario: oc.Guard.Scenario, Detector: oc.Guard.Detector,
				Direction: req.Direction, Verdict: oc.Result.Verdict, Score: oc.Result.Score,
				LatencyMs: oc.Elapsed.Milliseconds(), Spans: spans,
			})
			h.Metrics.ObserveGuard(req.App, req.Direction, oc)
			if oc.Result.Verdict == "FAIL" {
				res.Verdict = "FAIL"
			}
		}
		mutated, block, actions := detector.ApplyActions(current, outcomes)
		res.Actions = append(res.Actions, actions...)
		for _, a := range actions {
			h.Metrics.ObserveAction(req.App, req.Direction, a)
		}
		if block {
			res.Verdict = "FAIL"
			break
		}
		current = mutated
	}
	if current != req.Text {
		res.Mutated = current
	}
	WriteJSON(w, http.StatusOK, res)
}
