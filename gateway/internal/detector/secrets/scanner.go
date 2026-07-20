// Package secrets is the in-process, deterministic secrets detector
// (spec §4.3.2). Runs inside the gateway to avoid a network hop on the
// hottest path.
//
// Layered flow per spec:
//   1. Keyword prefilter (Aho-Corasick over rule keywords)
//   2. Targeted regex per rule
//   3. Shannon entropy check (base64/hex windows) for generic fallback
//   4. Optional structural validators (JWT for now; Luhn lives in PII)
//
// Same input + same ruleset version ⇒ same verdict, always.
package secrets

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

//go:embed rules.json
var defaultRulesJSON []byte

// DetectorID / Version are the pinned identifiers surfaced in policies /
// decision events. Version reflects the ruleset digest (bumping the JSON
// bumps this value via CI).
const (
	DetectorID = "secretscan"
	Version    = "0.1.0"
)

// Rule is a compiled detection rule.
type Rule struct {
	ID          string
	Description string
	Regex       *regexp.Regexp
	Keywords    []string
	Confidence  float64
	EntropyMin  float64
	Validators  []string
}

// Scanner is safe for concurrent Scan calls (rules are compiled once).
type Scanner struct {
	rules   []*Rule
	// Aho-Corasick trie over the union of all rule keywords.
	prefilter *ahoTrie
	// Map from a matched keyword → rules that use it (fan-in).
	byKeyword map[string][]*Rule
	// Rules with no keywords (always checked).
	global []*Rule
}

// Span is a byte-offset region in the scanned text.
type Span struct {
	Start      int
	End        int
	Label      string
	Confidence float64
}

// LoadDefault builds a Scanner from the embedded rules.json.
func LoadDefault() (*Scanner, error) {
	return Load(defaultRulesJSON)
}

type rulesFile struct {
	Title   string `json:"title"`
	Version string `json:"version"`
	Rules   []struct {
		ID          string   `json:"id"`
		Description string   `json:"description"`
		Regex       string   `json:"regex"`
		Keywords    []string `json:"keywords"`
		Confidence  float64  `json:"confidence"`
		EntropyMin  float64  `json:"entropy_min"`
		Validators  []string `json:"validators"`
	} `json:"rules"`
}

// Load compiles a ruleset from a JSON byte slice.
func Load(data []byte) (*Scanner, error) {
	var f rulesFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("secrets rules: parse: %w", err)
	}
	s := &Scanner{byKeyword: map[string][]*Rule{}}
	var allKeywords []string
	for _, r := range f.Rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			return nil, fmt.Errorf("secrets rule %q: bad regex: %w", r.ID, err)
		}
		rr := &Rule{
			ID: r.ID, Description: r.Description, Regex: re,
			Keywords: r.Keywords, Confidence: r.Confidence,
			EntropyMin: r.EntropyMin, Validators: r.Validators,
		}
		s.rules = append(s.rules, rr)
		if len(rr.Keywords) == 0 {
			s.global = append(s.global, rr)
			continue
		}
		for _, k := range rr.Keywords {
			s.byKeyword[k] = append(s.byKeyword[k], rr)
			allKeywords = append(allKeywords, k)
		}
	}
	s.prefilter = buildAho(allKeywords)
	return s, nil
}

// Scan returns non-overlapping high-confidence spans, sorted by offset.
// Threshold selects the minimum confidence to include; deterministic secrets
// use threshold=1.0 in policies, so anything below the rule confidence is
// dropped.
func (s *Scanner) Scan(text string, threshold float64) []Span {
	if len(text) == 0 {
		return nil
	}
	hits := map[*Rule]bool{}
	// Aho-Corasick prefilter — collect the subset of rules whose keywords appear.
	if s.prefilter != nil {
		for _, kw := range s.prefilter.matchKeywords(text) {
			for _, r := range s.byKeyword[kw] {
				hits[r] = true
			}
		}
	}
	// Global rules (no keyword) are always considered.
	for _, r := range s.global {
		hits[r] = true
	}

	var out []Span
	for r := range hits {
		if r.Confidence < threshold && r.EntropyMin == 0 {
			continue
		}
		locs := r.Regex.FindAllStringSubmatchIndex(text, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			match := text[start:end]

			conf := r.Confidence
			if r.EntropyMin > 0 {
				h := shannonEntropy(match)
				if h < r.EntropyMin {
					continue
				}
				// Scale confidence up as entropy exceeds threshold.
				conf = math.Min(1.0, r.Confidence+0.1*(h-r.EntropyMin))
			}
			if !runValidators(r.Validators, match) {
				continue
			}
			if conf < threshold {
				continue
			}
			out = append(out, Span{Start: start, End: end, Label: r.ID, Confidence: conf})
		}
	}
	return dedupOverlaps(out)
}

// Score returns the maximum span confidence in [0,1]. Empty = 0.
func (s *Scanner) Score(spans []Span) float64 {
	var m float64
	for _, sp := range spans {
		if sp.Confidence > m {
			m = sp.Confidence
		}
	}
	return m
}

// dedupOverlaps keeps the highest-confidence span in any overlapping range.
// This turns "generic-high-entropy also matched the AWS key" into just the
// stronger AWS-key span.
func dedupOverlaps(spans []Span) []Span {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].Confidence > spans[j].Confidence
	})
	out := spans[:0]
	var last *Span
	for i := range spans {
		s := &spans[i]
		if last != nil && s.Start < last.End {
			// Overlap. Keep the higher-confidence one.
			if s.Confidence > last.Confidence {
				*last = *s
			}
			continue
		}
		out = append(out, *s)
		last = &out[len(out)-1]
	}
	return out
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func runValidators(names []string, match string) bool {
	for _, n := range names {
		switch n {
		case "jwt_structural":
			if !isStructuralJWT(match) {
				return false
			}
		}
	}
	return true
}

func isStructuralJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 && len(parts[0]) >= 4 && len(parts[1]) >= 4 && len(parts[2]) >= 4
}
