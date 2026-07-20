package detector

import (
	"testing"

	"github.com/guardx/gateway/internal/policy"
)

func TestApplyActions_ShadowGuardNeverBlocksOrMutates(t *testing.T) {
	// Fake Stripe-format value composed at runtime — GH push-protection
	// blocks any literal sk_(live|test)_ + 24 alphanumerics in source.
	text := "sk_" + "test" + "_" + "ABCDEFGHIJKLMNOPQRSTUVWX" + " and other stuff"
	// A live secrets guard AND a shadow safety guard both FAIL. Only the live
	// one may act; the shadow one is a diagnostic no-op.
	outcomes := []GuardOutcome{
		{
			Guard: policy.Guard{ID: "g-safety-shadow", OnFail: "block", Shadow: true},
			Result: Result{
				Verdict: "FAIL", Score: 0.9,
				Spans: []Span{{Start: 0, End: 32, Label: "unsafe"}},
			},
		},
		{
			Guard: policy.Guard{ID: "g-secrets", OnFail: "redact"},
			Result: Result{
				Verdict: "FAIL", Score: 0.99,
				Spans: []Span{{Start: 0, End: 32, Label: "stripe-secret"}},
			},
		},
	}
	got, block, actions := ApplyActions(text, outcomes)
	if block {
		t.Fatal("shadow guard should not cause hard block")
	}
	if !contains(got, "[stripe-secret-REDACTED]") {
		t.Fatalf("live guard redaction should apply: %q", got)
	}
	// Actions should only reflect the live guard.
	if !containsAny(actions, "redact") || containsAny(actions, "block") {
		t.Fatalf("shadow should not appear in actions; got %v", actions)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func containsAny(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
