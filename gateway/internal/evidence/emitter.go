// Package evidence emits decision events. M0: stdout JSONL sink.
// M2 replaces the sink with a Kafka producer (fire-and-forget, local disk
// spool on outage — never blocks the response path).
package evidence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"
)

// Event is the on-wire decision event per spec §4.4.
type Event struct {
	EventID       string    `json:"event_id"`
	Timestamp     time.Time `json:"ts"`
	Tenant        string    `json:"tenant"`
	App           string    `json:"app"`
	Env           string    `json:"env"`
	RequestID     string    `json:"request_id"`
	Policy        string    `json:"policy"`         // policy_id@version
	BundleSeq     int64     `json:"bundle_seq"`
	GuardID       string    `json:"guard_id,omitempty"`
	Scenario      string    `json:"scenario,omitempty"`
	Detector      string    `json:"detector,omitempty"`
	Direction     string    `json:"direction,omitempty"`
	Verdict       string    `json:"verdict"`
	Score         float64   `json:"score"`
	ActionTaken   string    `json:"action_taken,omitempty"`
	LatencyMs     int64     `json:"latency_ms"`
	EvidenceMode  string    `json:"evidence_mode,omitempty"`
	Spans         []SpanRef `json:"spans,omitempty"`
	TextHash      string    `json:"text_hash,omitempty"`
	PrevEventHash string    `json:"prev_event_hash,omitempty"`
	EventHash     string    `json:"event_hash,omitempty"`
	IsShadow      bool      `json:"is_shadow,omitempty"`
}

// SpanRef mirrors the detector's Span for evidence purposes. Kept minimal —
// the evidence_mode gate (spec §4.4) will filter these in M2.
type SpanRef struct {
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Label      string  `json:"label"`
	Confidence float64 `json:"confidence"`
}

// Emitter is the sink interface. M0 → StdoutEmitter; M2 → KafkaEmitter.
type Emitter interface {
	Emit(evt Event)
}

// StdoutEmitter writes one JSON object per line to the provided logger.
type StdoutEmitter struct {
	Log *slog.Logger
}

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *StdoutEmitter) Emit(evt Event) {
	if evt.EventID == "" {
		evt.EventID = newEventID()
	}
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	b, err := json.Marshal(evt)
	if err != nil {
		s.Log.Error("evidence: marshal failed", "err", err)
		return
	}
	s.Log.Info("evidence", "event", string(b))
}
