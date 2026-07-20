package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// HTTPBackend calls a detector service over HTTP+JSON. Message shapes mirror
// proto/detector.proto; when we switch to real gRPC the caller doesn't change.
//
// Includes a minimal circuit breaker: consecutive 5xx/timeout errors open the
// circuit for a cool-down window; while open, Check returns immediately.
type HTTPBackend struct {
	name     string
	scenario string
	baseURL  string
	client   *http.Client

	// Circuit breaker.
	failures      atomic.Int32
	openUntil     atomic.Int64  // unix nano; 0 = closed
	failThreshold int32
	openWindow    time.Duration
}

// HTTPBackendConfig captures per-backend knobs. Defaults are safe.
type HTTPBackendConfig struct {
	Name          string
	Scenario      string
	BaseURL       string        // e.g. http://pii:9100
	Timeout       time.Duration // per-call timeout (in addition to ctx deadline)
	FailThreshold int32         // consecutive errors before opening
	OpenWindow    time.Duration // how long the circuit stays open
}

func NewHTTPBackend(cfg HTTPBackendConfig) *HTTPBackend {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 400 * time.Millisecond
	}
	if cfg.FailThreshold == 0 {
		cfg.FailThreshold = 5
	}
	if cfg.OpenWindow == 0 {
		cfg.OpenWindow = 15 * time.Second
	}
	return &HTTPBackend{
		name:          cfg.Name,
		scenario:      cfg.Scenario,
		baseURL:       cfg.BaseURL,
		client:        &http.Client{Timeout: cfg.Timeout},
		failThreshold: cfg.FailThreshold,
		openWindow:    cfg.OpenWindow,
	}
}

func (b *HTTPBackend) Name() string     { return b.name }
func (b *HTTPBackend) Scenario() string { return b.scenario }

type httpCheckRequest struct {
	RequestID  string         `json:"request_id"`
	Text       string         `json:"text"`
	Direction  string         `json:"direction"`
	Config     map[string]any `json:"config"`
	Metadata   map[string]string `json:"metadata"`
	DeadlineMs int            `json:"deadline_ms"`
}

type httpCheckResponse struct {
	DetectorVersion string `json:"detector_version"`
	Score           float64 `json:"score"`
	Verdict         string `json:"verdict"`
	Spans           []Span `json:"spans"`
	Explanation     string `json:"explanation"`
	LatencyMs       int64  `json:"latency_ms"`
}

func (b *HTTPBackend) Check(ctx context.Context, req Request) (Result, error) {
	if openUntil := b.openUntil.Load(); openUntil > 0 && time.Now().UnixNano() < openUntil {
		return Result{Verdict: "ERROR", Explanation: "circuit open"},
			errors.New("circuit open")
	}
	deadline, _ := ctx.Deadline()
	remaining := int(400)
	if !deadline.IsZero() {
		remaining = int(time.Until(deadline).Milliseconds())
		if remaining <= 0 {
			return Result{Verdict: "ERROR"}, errors.New("context deadline exceeded")
		}
	}

	body, err := json.Marshal(httpCheckRequest{
		RequestID:  req.RequestID,
		Text:       req.Text,
		Direction:  req.Direction,
		Config:     req.Config,
		Metadata:   map[string]string{"app": req.App},
		DeadlineMs: remaining,
	})
	if err != nil {
		return Result{Verdict: "ERROR"}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", b.baseURL+"/v1/check", bytes.NewReader(body))
	if err != nil {
		return Result{Verdict: "ERROR"}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(httpReq)
	if err != nil {
		b.recordFailure()
		return Result{Verdict: "ERROR"}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		b.recordFailure()
		return Result{Verdict: "ERROR"}, fmt.Errorf("detector %s: HTTP %d", b.name, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return Result{Verdict: "ERROR"}, fmt.Errorf("detector %s: HTTP %d", b.name, resp.StatusCode)
	}

	var body2 httpCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&body2); err != nil {
		return Result{Verdict: "ERROR"}, err
	}
	b.recordSuccess()
	return Result{
		Verdict:         body2.Verdict,
		Score:           body2.Score,
		DetectorVersion: body2.DetectorVersion,
		Spans:           body2.Spans,
		Explanation:     body2.Explanation,
		LatencyMs:       body2.LatencyMs,
	}, nil
}

func (b *HTTPBackend) recordFailure() {
	f := b.failures.Add(1)
	if f >= b.failThreshold {
		b.openUntil.Store(time.Now().Add(b.openWindow).UnixNano())
	}
}

func (b *HTTPBackend) recordSuccess() {
	b.failures.Store(0)
	b.openUntil.Store(0)
}
