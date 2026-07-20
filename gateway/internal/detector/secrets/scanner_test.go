package secrets

import (
	"strings"
	"testing"
)

func loadScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScanner_DetectsAWSAccessKey(t *testing.T) {
	s := loadScanner(t)
	text := "our access key is AKIAIOSFODNN7EXAMPLE and password"
	spans := s.Scan(text, 0.9)
	if len(spans) == 0 {
		t.Fatal("expected AWS key detection")
	}
	got := spans[0]
	if got.Label != "aws-access-key" {
		t.Fatalf("wrong label: %+v", got)
	}
	if text[got.Start:got.End] != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("wrong span text: %q", text[got.Start:got.End])
	}
}

func TestScanner_DetectsGitHubPAT(t *testing.T) {
	s := loadScanner(t)
	// GitHub PATs are ghp_ + exactly 36 base62 chars.
	text := "token: ghp_1234567890abcdefghij1234567890ABCDEF end"
	spans := s.Scan(text, 0.9)
	if len(spans) == 0 {
		t.Fatal("expected GitHub PAT detection")
	}
	if spans[0].Label != "github-pat" {
		t.Fatalf("wrong label: %+v", spans[0])
	}
}

func TestScanner_DetectsStripeSecret(t *testing.T) {
	s := loadScanner(t)
	text := "STRIPE_KEY=" + "sk_" + "test" + "_" + "abcdefghijklmnopqrstuvwxABCD"
	spans := s.Scan(text, 0.9)
	if len(spans) == 0 {
		t.Fatal("expected Stripe key")
	}
}

func TestScanner_DetectsPEMPrivateKey(t *testing.T) {
	s := loadScanner(t)
	text := "here is the key: -----BEGIN RSA PRIVATE KEY-----\nMIIEow..."
	spans := s.Scan(text, 1.0)
	if len(spans) == 0 {
		t.Fatal("expected PEM key detection")
	}
}

func TestScanner_JWTValidatorRejectsTwoDots(t *testing.T) {
	s := loadScanner(t)
	// Something that regex might catch loosely — validator should still gate.
	text := "not-a-jwt eyAAAAAAAAAA.eyAAAAAAAAAA"
	spans := s.Scan(text, 0.8)
	for _, sp := range spans {
		if sp.Label == "jwt" {
			t.Fatalf("jwt validator should have rejected: %+v", sp)
		}
	}
}

func TestScanner_CleanTextProducesNoSpans(t *testing.T) {
	s := loadScanner(t)
	text := "Hello, this is a normal customer service response with no secrets."
	spans := s.Scan(text, 0.9)
	for _, sp := range spans {
		t.Errorf("false positive on clean text: %+v (%q)", sp, text[sp.Start:sp.End])
	}
}

func TestScanner_OverlapDedupPrefersSpecific(t *testing.T) {
	s := loadScanner(t)
	// aws-access-key vs generic-high-entropy could both match — the more
	// specific rule should win.
	text := "AWS: AKIAIOSFODNN7EXAMPLE"
	spans := s.Scan(text, 0.9)
	if len(spans) != 1 {
		t.Fatalf("expected dedup to leave one span, got %d: %+v", len(spans), spans)
	}
	if spans[0].Label != "aws-access-key" {
		t.Fatalf("dedup kept lower-confidence rule: %+v", spans[0])
	}
}

func TestAho_MatchesKeywords(t *testing.T) {
	trie := buildAho([]string{"AKIA", "ghp_", "sk_live_"})
	got := trie.matchKeywords("we have ghp_TOKEN plus AKIA... and sk_live_abc")
	set := map[string]bool{}
	for _, k := range got {
		set[strings.ToLower(k)] = true
	}
	for _, want := range []string{"akia", "ghp_", "sk_live_"} {
		if !set[want] {
			t.Errorf("missing keyword %q in %v", want, got)
		}
	}
}
