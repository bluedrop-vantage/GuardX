package detector

import (
	"sort"
	"strings"
)

// ApplyActions mutates `text` per each outcome's on_fail action, applied over
// its returned spans, and reports whether the result should hard-block.
//
// Returns:
//   - the possibly-mutated text
//   - true if any guard demands a hard block (block / block_and_explain)
//   - a distilled list of action strings (for evidence + response headers)
func ApplyActions(text string, outcomes []GuardOutcome) (mutated string, block bool, actionsTaken []string) {
	// Aggregate spans across all FAIL outcomes so we can rewrite once.
	type edit struct {
		start, end int
		label      string
		action     string
	}
	var edits []edit
	for _, oc := range outcomes {
		if oc.Result.Verdict != "FAIL" {
			continue
		}
		// Shadow guards are diagnostic — their verdicts are captured as evidence
		// but they never mutate text or block. This is the safety net that lets
		// tuner-proposed policies observe live traffic before promotion (§5.3).
		if oc.Guard.Shadow {
			continue
		}
		switch oc.Guard.OnFail {
		case "block", "block_and_explain":
			block = true
			actionsTaken = append(actionsTaken, oc.Guard.OnFail)
			continue
		case "redact":
			for _, s := range oc.Result.Spans {
				edits = append(edits, edit{s.Start, s.End, s.Label, "redact"})
			}
			actionsTaken = append(actionsTaken, "redact")
		case "mask":
			for _, s := range oc.Result.Spans {
				edits = append(edits, edit{s.Start, s.End, s.Label, "mask"})
			}
			actionsTaken = append(actionsTaken, "mask")
		case "flag":
			actionsTaken = append(actionsTaken, "flag")
			// no mutation
		case "reask", "rewrite":
			// M1 scope: rewrite/reask deferred (need model round-trip).
			actionsTaken = append(actionsTaken, oc.Guard.OnFail+":deferred")
		}
	}
	if block || len(edits) == 0 {
		return text, block, dedupStrings(actionsTaken)
	}
	// Sort by start ascending; drop overlaps by keeping earliest-starting.
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var out strings.Builder
	out.Grow(len(text) + 32*len(edits))
	pos := 0
	for _, e := range edits {
		if e.start < pos {
			continue // overlap — already covered
		}
		out.WriteString(text[pos:e.start])
		switch e.action {
		case "redact":
			out.WriteString("[")
			out.WriteString(e.label)
			out.WriteString("-REDACTED]")
		case "mask":
			// Preserve last 4 chars if the match is long enough.
			seg := text[e.start:e.end]
			if len(seg) > 4 {
				out.WriteString(strings.Repeat("*", len(seg)-4))
				out.WriteString(seg[len(seg)-4:])
			} else {
				out.WriteString(strings.Repeat("*", len(seg)))
			}
		}
		pos = e.end
	}
	out.WriteString(text[pos:])
	return out.String(), false, dedupStrings(actionsTaken)
}

func dedupStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
