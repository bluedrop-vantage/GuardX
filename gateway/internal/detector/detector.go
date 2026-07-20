// Package detector routes guard evaluations to the right backend and applies
// on_fail actions to text based on returned spans.
//
// Two backend classes:
//   1. In-process (secrets) — no network hop, µs-scale.
//   2. HTTP+gRPC-shaped services (PII, safety, hallucination in later
//      milestones) — dial pool + per-call deadline + circuit breaker.
//
// All backends return the shared Result type below so the dispatcher and
// action applier don't care which is which.
package detector

import (
	"context"
	"time"

	"github.com/guardx/gateway/internal/policy"
)

// Result is the detector output the dispatcher hands the action layer.
type Result struct {
	Verdict         string    // PASS | FAIL | ERROR | NEEDS_ESCALATION
	Score           float64
	DetectorVersion string
	Spans           []Span
	Explanation     string
	LatencyMs       int64
}

// Span is a byte-offset region tagged with the entity/rule label.
type Span struct {
	Start      int
	End        int
	Label      string
	Confidence float64
}

// Backend is a detector implementation. Backends must be safe for concurrent
// use across goroutines.
type Backend interface {
	Name() string             // e.g. "secretscan@0.1.0"
	Scenario() string         // "secrets" | "pii" | ...
	Check(ctx context.Context, req Request) (Result, error)
}

// Request is one call to a backend. `Config` carries the parsed guard.config.
type Request struct {
	RequestID string
	Text      string
	Direction string // "input" | "output"
	Config    map[string]any
	App       string
}

// Registry maps detector id@version → Backend, keyed by the string that
// appears in guard.detector.
type Registry struct {
	byID map[string]Backend
}

func NewRegistry() *Registry {
	return &Registry{byID: map[string]Backend{}}
}

func (r *Registry) Register(b Backend) {
	r.byID[b.Name()] = b
}

// Get returns the backend for a guard's pinned detector, or nil.
func (r *Registry) Get(name string) Backend {
	return r.byID[name]
}

// GuardOutcome pairs a guard with what a backend said about it. `Err` is set
// when a backend erroed or timed out; the caller applies fail_mode.
type GuardOutcome struct {
	Guard   policy.Guard
	Result  Result
	Err     error
	Elapsed time.Duration
}
