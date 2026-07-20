package detector

import (
	"context"

	"github.com/guardx/gateway/internal/detector/secrets"
)

// SecretsBackend wraps the in-process secrets scanner as a Backend so the
// dispatcher can treat it uniformly with network detectors.
type SecretsBackend struct {
	scanner *secrets.Scanner
	name    string
}

func NewSecretsBackend() (*SecretsBackend, error) {
	s, err := secrets.LoadDefault()
	if err != nil {
		return nil, err
	}
	return &SecretsBackend{
		scanner: s,
		name:    secrets.DetectorID + "@" + secrets.Version,
	}, nil
}

func (b *SecretsBackend) Name() string     { return b.name }
func (b *SecretsBackend) Scenario() string { return "secrets" }

func (b *SecretsBackend) Check(ctx context.Context, req Request) (Result, error) {
	// Deterministic + fast — no need to plumb ctx into the scanner.
	// Threshold is applied by the dispatcher; scanner returns high-confidence
	// spans at 0.9+ so we set a low internal cutoff here to preserve fidelity.
	spans := b.scanner.Scan(req.Text, 0.5)
	out := make([]Span, len(spans))
	for i, s := range spans {
		out[i] = Span{Start: s.Start, End: s.End, Label: s.Label, Confidence: s.Confidence}
	}
	score := b.scanner.Score(spans)
	verdict := "PASS"
	if score > 0 {
		verdict = "FAIL"
	}
	return Result{
		Verdict:         verdict,
		Score:           score,
		DetectorVersion: secrets.Version,
		Spans:           out,
		Explanation:     "in-process secretscan",
	}, nil
}
