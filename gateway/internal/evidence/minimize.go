package evidence

import (
	"crypto/sha256"
	"encoding/hex"
)

// Minimize enforces the per-guard evidence_mode at emit time. Defense in depth:
// the Control API applies the same policy on ingest.
//
//	none       drop spans; keep hashes
//	spans      keep spans (no text); default for PII policies
//	full_text  keep spans; payload_ref filled by caller (M3 wires KMS envelope)
func Minimize(mode string, evt Event) Event {
	if mode == "" {
		mode = "spans"
	}
	evt.EvidenceMode = mode
	switch mode {
	case "none":
		evt.Spans = nil
	case "spans":
		// nothing to strip
	case "full_text":
		// nothing to strip; payload writer handles the payload_ref itself
	default:
		// Unknown mode falls back to spans (conservative).
		evt.EvidenceMode = "spans"
	}
	return evt
}

// TextHashSHA256 returns the "sha256:<hex>" digest used in text_hash. Callers
// pass the exact text a guard evaluated so integrity checks are reproducible
// even under evidence_mode=none.
func TextHashSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}
