package bundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func signedEnvelope(t *testing.T, manifest map[string]any) (*Envelope, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := CanonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, canon)
	sum := sha256.Sum256(canon)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return &Envelope{
		BundleSeq:    1,
		Manifest:     raw,
		ManifestHash: "sha256:" + hex.EncodeToString(sum[:]),
		SignatureB64: base64.StdEncoding.EncodeToString(sig),
		SigningKeyID: "test-key",
	}, pub
}

func manifestReferencing(detector string, detectorTable []map[string]any) (map[string]any, string) {
	policyDoc := map[string]any{
		"metadata": map[string]any{"id": "p1", "version": "1.0.0"},
		"spec": map[string]any{
			"applies_to": map[string]any{"apps": []any{"a"}, "environments": []any{"prod"}},
			"defaults":   map[string]any{"fail_mode": "closed"},
			"guards": []any{
				map[string]any{
					"id":        "g1",
					"scenario":  "pii",
					"detector":  detector,
					"direction": []any{"output"},
					"on_fail":   "flag",
				},
			},
		},
	}
	pcanon, _ := CanonicalJSON(policyDoc)
	psum := sha256.Sum256(pcanon)
	pdocRaw, _ := json.Marshal(policyDoc)
	m := map[string]any{
		"tenant": "acme", "environment": "prod", "bundle_seq": 1,
		"created_at": "2026-07-17T00:00:00Z", "max_age_hours": 72,
		"policies": []any{
			map[string]any{
				"policy_id":     "p1",
				"version":       "1.0.0",
				"document_hash": "sha256:" + hex.EncodeToString(psum[:]),
				// The manifest is canonicalized as-a-whole so the embedded
				// document has to be the same map shape, not a RawMessage.
				"document": policyDoc,
			},
		},
		"detectors": func() []any {
			out := make([]any, 0, len(detectorTable))
			for _, d := range detectorTable {
				out = append(out, d)
			}
			return out
		}(),
	}
	_ = pdocRaw
	return m, ""
}

func TestVerify_RejectsBundleWithUnpinnedDetector(t *testing.T) {
	m, _ := manifestReferencing(
		"presidio-ensemble@1.4.0",
		[]map[string]any{
			{"detector_id": "presidio-ensemble", "version": "1.4.0", "image_digest": ""},
		},
	)
	env, pub := signedEnvelope(t, m)
	trust := &StaticTrustStore{Keys: map[string]ed25519.PublicKey{"test-key": pub}}
	_, err := Verify(env, trust)
	if err == nil {
		t.Fatal("expected unpinned-detector rejection")
	}
	if !strings.Contains(err.Error(), "unpinned") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestVerify_RejectsBundleMissingDetectorRow(t *testing.T) {
	m, _ := manifestReferencing(
		"nli-groundedness@2.1.0",
		[]map[string]any{}, // detector table doesn't include it
	)
	env, pub := signedEnvelope(t, m)
	trust := &StaticTrustStore{Keys: map[string]ed25519.PublicKey{"test-key": pub}}
	_, err := Verify(env, trust)
	if err == nil {
		t.Fatal("expected missing-detector rejection")
	}
	if !strings.Contains(err.Error(), "missing from bundle manifest") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestVerify_AcceptsBuiltinPin(t *testing.T) {
	m, _ := manifestReferencing(
		"secretscan@0.1.0",
		[]map[string]any{
			{"detector_id": "secretscan", "version": "0.1.0", "image_digest": "builtin"},
		},
	)
	env, pub := signedEnvelope(t, m)
	trust := &StaticTrustStore{Keys: map[string]ed25519.PublicKey{"test-key": pub}}
	if _, err := Verify(env, trust); err != nil {
		t.Fatalf("builtin pin should be accepted: %v", err)
	}
}

func TestVerify_AcceptsProperOCIDigest(t *testing.T) {
	m, _ := manifestReferencing(
		"presidio-ensemble@1.4.0",
		[]map[string]any{
			{"detector_id": "presidio-ensemble", "version": "1.4.0",
			 "image_digest": "sha256:abc123def456"},
		},
	)
	env, pub := signedEnvelope(t, m)
	trust := &StaticTrustStore{Keys: map[string]ed25519.PublicKey{"test-key": pub}}
	if _, err := Verify(env, trust); err != nil {
		t.Fatalf("expected accept: %v", err)
	}
}
