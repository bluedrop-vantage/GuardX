package detector

import (
	"strings"
	"testing"

	"github.com/guardx/gateway/internal/policy"
)

func TestApplyActions_Redact(t *testing.T) {
	text := "SSN is 123-45-6789 on file."
	outcomes := []GuardOutcome{{
		Guard: policy.Guard{ID: "g", OnFail: "redact"},
		Result: Result{
			Verdict: "FAIL", Score: 0.95,
			Spans: []Span{{Start: 7, End: 18, Label: "SSN", Confidence: 0.95}},
		},
	}}
	got, block, actions := ApplyActions(text, outcomes)
	if block {
		t.Fatal("should not block on redact")
	}
	if got != "SSN is [SSN-REDACTED] on file." {
		t.Fatalf("unexpected redaction: %q", got)
	}
	if len(actions) != 1 || actions[0] != "redact" {
		t.Fatalf("actions: %v", actions)
	}
}

func TestApplyActions_MaskKeepsLast4(t *testing.T) {
	text := "Card 4242424242424242 charged."
	outcomes := []GuardOutcome{{
		Guard: policy.Guard{ID: "g", OnFail: "mask"},
		Result: Result{
			Verdict: "FAIL", Score: 0.99,
			Spans: []Span{{Start: 5, End: 21, Label: "CREDIT_CARD", Confidence: 0.99}},
		},
	}}
	got, _, _ := ApplyActions(text, outcomes)
	if !strings.Contains(got, "************4242") {
		t.Fatalf("mask did not keep last 4: %q", got)
	}
}

func TestApplyActions_BlockShortCircuits(t *testing.T) {
	// Fake Stripe-format value composed at runtime so the literal string never
	// appears in source (GitHub push-protection blocks any sk_(live|test)_
	// followed by 24+ alphanumeric chars in tracked files).
	text := "sk_" + "test" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	outcomes := []GuardOutcome{{
		Guard: policy.Guard{ID: "g", OnFail: "block"},
		Result: Result{
			Verdict: "FAIL", Score: 0.99,
			Spans: []Span{{Start: 0, End: 32, Label: "stripe-secret"}},
		},
	}}
	_, block, actions := ApplyActions(text, outcomes)
	if !block {
		t.Fatal("expected hard block")
	}
	if len(actions) != 1 || actions[0] != "block" {
		t.Fatalf("actions: %v", actions)
	}
}

func TestApplyActions_PassIsNoop(t *testing.T) {
	text := "hello world"
	outcomes := []GuardOutcome{{
		Guard:  policy.Guard{ID: "g", OnFail: "redact"},
		Result: Result{Verdict: "PASS"},
	}}
	got, block, actions := ApplyActions(text, outcomes)
	if got != text || block || len(actions) != 0 {
		t.Fatalf("PASS should be no-op; got=%q block=%v actions=%v", got, block, actions)
	}
}

func TestApplyActions_MultipleRedactionsInOnePass(t *testing.T) {
	text := "SSN 111-22-3333 and card 4242 4242 4242 4242 done."
	outcomes := []GuardOutcome{{
		Guard: policy.Guard{ID: "g", OnFail: "redact"},
		Result: Result{
			Verdict: "FAIL",
			Spans: []Span{
				{Start: 4, End: 15, Label: "SSN"},
				{Start: 25, End: 44, Label: "CREDIT_CARD"},
			},
		},
	}}
	got, _, _ := ApplyActions(text, outcomes)
	if !strings.Contains(got, "[SSN-REDACTED]") || !strings.Contains(got, "[CREDIT_CARD-REDACTED]") {
		t.Fatalf("expected both redactions in: %q", got)
	}
}
