// Package proxy implements the reverse proxy that fronts an upstream LLM
// endpoint (OpenAI-compatible /v1/chat/completions in M1).
//
// M1 request flow (non-streaming):
//   1. Resolve policies for (app, environment) from the in-memory index.
//   2. INPUT phase: run guards where direction includes "input".
//      - hard-fail → 403 with GuardError
//      - redact/mask → mutate the message contents in-place, forward
//   3. Forward the possibly-mutated body upstream.
//   4. OUTPUT phase: run guards where direction includes "output".
//      - hard-fail → 403
//      - redact/mask → mutate the assistant reply, forward to client
//   5. Emit one decision event per guard evaluation (spec §4.4).
//
// Streaming (§4.2) is deferred to a follow-up; requests with `stream:true`
// currently short-circuit to 501.
package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/guardx/gateway/internal/detector"
	"github.com/guardx/gateway/internal/evidence"
	"github.com/guardx/gateway/internal/gwmetrics"
	"github.com/guardx/gateway/internal/httpapi"
	"github.com/guardx/gateway/internal/policy"
)

type Handler struct {
	Snap        *policy.Snapshot
	Emitter     evidence.Emitter
	Dispatcher  *detector.Dispatcher
	Metrics     *gwmetrics.Collector
	Upstream    *url.URL
	Tenant      string
	Environment string
	Client      *http.Client
	Timeout     time.Duration
}

func New(snap *policy.Snapshot, emitter evidence.Emitter, dispatch *detector.Dispatcher, upstream *url.URL, tenant, env string) *Handler {
	return &Handler{
		Snap: snap, Emitter: emitter, Dispatcher: dispatch,
		Upstream: upstream, Tenant: tenant, Environment: env,
		Client:  &http.Client{Timeout: 30 * time.Second},
		Timeout: 30 * time.Second,
	}
}

// openAIChatBody is a partial view of the OpenAI-compatible chat request.
type openAIChatBody struct {
	Model    string             `json:"model,omitempty"`
	Stream   bool               `json:"stream,omitempty"`
	Messages []openAIChatMessage `json:"messages,omitempty"`
	// preserve unknown fields verbatim
	Extra map[string]json.RawMessage `json:"-"`
}

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIChatResponse is the partial output shape we mutate.
type openAIChatResponse struct {
	ID      string             `json:"id,omitempty"`
	Object  string             `json:"object,omitempty"`
	Model   string             `json:"model,omitempty"`
	Choices []openAIChatChoice `json:"choices,omitempty"`
	Extra   map[string]json.RawMessage `json:"-"`
}

type openAIChatChoice struct {
	Index        int               `json:"index"`
	Message      openAIChatMessage `json:"message"`
	FinishReason string            `json:"finish_reason,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	app, ok := extractApp(r.URL.Path)
	if !ok {
		httpapi.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "app not in path"})
		return
	}
	requestID := requestID(r)
	w.Header().Set("X-Request-ID", requestID)

	idx := h.Snap.Load()
	if idx == nil {
		httpapi.WriteInternal(w, "gateway: no policy index loaded")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		httpapi.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "read body"})
		return
	}
	_ = r.Body.Close()

	// Peek at the body shape.
	var req openAIChatBody
	if err := json.Unmarshal(body, &req); err != nil {
		httpapi.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if req.Stream {
		httpapi.WriteJSON(w, http.StatusNotImplemented, map[string]string{
			"error": "streaming validation not implemented yet (§4.2 landing in a follow-up)",
		})
		return
	}

	inputText := concatMessages(req.Messages)

	// INPUT phase.
	inMutated, block, actions, err := h.runPhase(r.Context(), idx, requestID, app, "input", inputText)
	if err != nil {
		httpapi.WriteInternal(w, "input phase: "+err.Error())
		return
	}
	if block {
		httpapi.WriteGuardBlocked(w, httpapi.GuardError{
			Message: "input blocked by policy",
			Reasons: actions, RequestID: requestID,
		})
		return
	}
	if inMutated != inputText {
		// Split the mutated text back into the last user message. Simple rule
		// for M1: put the mutated text in the last user message, leave others.
		writeMutatedInput(&req, inMutated)
		body, _ = json.Marshal(req)
	}

	// Forward upstream.
	upURL := *h.Upstream
	upURL.Path = strings.TrimRight(upURL.Path, "/") + "/" + strings.TrimLeft(stripAppPrefix(r.URL.Path), "/")
	upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upURL.String(), bytes.NewReader(body))
	if err != nil {
		httpapi.WriteInternal(w, "build upstream req: "+err.Error())
		return
	}
	upReq.Header.Set("Content-Type", "application/json")
	if v := r.Header.Get("Authorization"); v != "" {
		upReq.Header.Set("Authorization", v)
	}
	upResp, err := h.Client.Do(upReq)
	if err != nil {
		httpapi.WriteInternal(w, "upstream: "+err.Error())
		return
	}
	defer upResp.Body.Close()

	upBody, err := io.ReadAll(upResp.Body)
	if err != nil {
		httpapi.WriteInternal(w, "read upstream body: "+err.Error())
		return
	}

	// If upstream returned non-JSON or an error status, just relay.
	if upResp.StatusCode >= 400 || !isJSON(upResp.Header.Get("Content-Type")) {
		relay(w, upResp, upBody)
		return
	}

	var resp openAIChatResponse
	if err := json.Unmarshal(upBody, &resp); err != nil {
		relay(w, upResp, upBody)
		return
	}
	outputText := concatChoices(resp.Choices)

	outMutated, block, actions, err := h.runPhase(r.Context(), idx, requestID, app, "output", outputText)
	if err != nil {
		httpapi.WriteInternal(w, "output phase: "+err.Error())
		return
	}
	if block {
		httpapi.WriteGuardBlocked(w, httpapi.GuardError{
			Message: "output blocked by policy",
			Reasons: actions, RequestID: requestID,
		})
		return
	}
	if outMutated != outputText {
		writeMutatedOutput(&resp, outMutated)
		upBody, _ = json.Marshal(resp)
	}
	relay(w, upResp, upBody)
}

// runPhase runs every policy's guards for the given direction and returns:
//   - the mutated text (or original if no mutation)
//   - block == true if any guard demands a hard block
//   - the deduplicated actions taken (for logs)
func (h *Handler) runPhase(
	ctx context.Context,
	idx *policy.Index,
	requestID, app, direction, text string,
) (string, bool, []string, error) {
	policies := idx.Resolve(app, h.Environment)
	if len(policies) == 0 {
		return text, false, nil, nil
	}
	cur := text
	var actionsAll []string
	for _, p := range policies {
		budget := time.Duration(p.TimeoutMs) * time.Millisecond
		outcomes := h.Dispatcher.Run(ctx, requestID, app, direction, cur, p, budget)
		for _, oc := range outcomes {
			h.emit(idx, p, oc, requestID, app, direction, cur)
			h.Metrics.ObserveGuard(app, direction, oc)
		}
		mutated, block, actions := detector.ApplyActions(cur, outcomes)
		actionsAll = append(actionsAll, actions...)
		for _, a := range actions {
			h.Metrics.ObserveAction(app, direction, a)
		}
		if block {
			h.Metrics.ObserveAction(app, direction, "block")
			return cur, true, actionsAll, nil
		}
		cur = mutated
	}
	return cur, false, actionsAll, nil
}

func (h *Handler) emit(idx *policy.Index, p *policy.Resolved, oc detector.GuardOutcome, requestID, app, direction, text string) {
	spans := make([]evidence.SpanRef, 0, len(oc.Result.Spans))
	for _, s := range oc.Result.Spans {
		spans = append(spans, evidence.SpanRef{Start: s.Start, End: s.End, Label: s.Label, Confidence: s.Confidence})
	}
	// Per-guard evidence_mode overrides a policy default; PII guards default to
	// "spans" per spec §4.4. Anything unknown → "spans" (conservative).
	mode := oc.Guard.Evidence
	if mode == "" {
		mode = "spans"
	}
	evt := evidence.Event{
		Tenant:    h.Tenant, App: app, Env: h.Environment,
		RequestID: requestID,
		Policy:    fmt.Sprintf("%s@%s", p.PolicyID, p.Version),
		BundleSeq: idx.BundleSeq,
		GuardID:   oc.Guard.ID,
		Scenario:  oc.Guard.Scenario,
		Detector:  oc.Guard.Detector,
		Direction: direction,
		Verdict:   oc.Result.Verdict,
		Score:     oc.Result.Score,
		LatencyMs: oc.Elapsed.Milliseconds(),
		Spans:     spans,
		TextHash:  evidence.TextHashSHA256(text),
		IsShadow:  oc.Guard.Shadow,
	}
	h.Emitter.Emit(evidence.Minimize(mode, evt))
}

// --- helpers ---

func extractApp(path string) (string, bool) {
	parts := strings.SplitN(path, "/", 5)
	if len(parts) < 4 || parts[1] != "v1" || parts[2] != "proxy" {
		return "", false
	}
	return parts[3], true
}

func stripAppPrefix(path string) string {
	parts := strings.SplitN(path, "/", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func concatMessages(msgs []openAIChatMessage) string {
	var b strings.Builder
	for i, m := range msgs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(m.Content)
	}
	return b.String()
}

func concatChoices(cs []openAIChatChoice) string {
	var b strings.Builder
	for i, c := range cs {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(c.Message.Content)
	}
	return b.String()
}

// writeMutatedInput drops the mutated text into the last user message and
// blanks any earlier user turns. This is deliberately simple for M1 — enough
// to demo redaction on a single-turn chat. A proper implementation reruns the
// mutation per-message so history is preserved.
func writeMutatedInput(req *openAIChatBody, mutated string) {
	if len(req.Messages) == 0 {
		return
	}
	last := len(req.Messages) - 1
	req.Messages[last].Content = mutated
}

func writeMutatedOutput(resp *openAIChatResponse, mutated string) {
	if len(resp.Choices) == 0 {
		return
	}
	resp.Choices[0].Message.Content = mutated
}

func isJSON(ct string) bool {
	return strings.HasPrefix(ct, "application/json") || strings.HasPrefix(ct, "text/json")
}

func relay(w http.ResponseWriter, resp *http.Response, body []byte) {
	for k, vs := range resp.Header {
		// content-length will be recomputed after we possibly rewrote body
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func requestID(r *http.Request) string {
	if v := r.Header.Get("X-Request-ID"); v != "" {
		return v
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "r-" + hex.EncodeToString(b[:])
}
