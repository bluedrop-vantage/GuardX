package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Envelope is the wire shape returned by the Control API bundle-pull endpoint.
type Envelope struct {
	Tenant       string          `json:"tenant"`
	Environment  string          `json:"environment"`
	BundleSeq    int64           `json:"bundle_seq"`
	Manifest     json.RawMessage `json:"manifest"`
	ManifestHash string          `json:"manifest_hash"`
	SignatureB64 string          `json:"signature_b64"`
	SigningKeyID string          `json:"signing_key_id"`
	CreatedAt    string          `json:"created_at"`
}

// Manifest is the parsed manifest doc.
type Manifest struct {
	Tenant       string           `json:"tenant"`
	Environment  string           `json:"environment"`
	BundleSeq    int64            `json:"bundle_seq"`
	CreatedAt    time.Time        `json:"created_at"`
	MaxAgeHours  int              `json:"max_age_hours"`
	Policies     []PolicyEntry    `json:"policies"`
	Detectors    []DetectorEntry  `json:"detectors"`
}

type PolicyEntry struct {
	PolicyID     string          `json:"policy_id"`
	Version      string          `json:"version"`
	DocumentHash string          `json:"document_hash"`
	Document     json.RawMessage `json:"document"`
}

type DetectorEntry struct {
	DetectorID  string `json:"detector_id"`
	Version     string `json:"version"`
	ImageDigest string `json:"image_digest"`
}

// TrustStore knows the public keys we trust for bundle signatures.
type TrustStore interface {
	PublicKey(keyID string) (ed25519.PublicKey, bool)
}

type StaticTrustStore struct {
	Keys map[string]ed25519.PublicKey
}

func (s *StaticTrustStore) PublicKey(id string) (ed25519.PublicKey, bool) {
	k, ok := s.Keys[id]
	return k, ok
}

// Verify checks the envelope's signature and manifest-hash commitments.
// Invariant I1: enforcement points never accept a policy that is unsigned or
// expired. `AgeExceeded()` on the returned manifest is the caller's next check.
func Verify(env *Envelope, trust TrustStore) (*Manifest, error) {
	if env == nil {
		return nil, errors.New("nil envelope")
	}
	pub, ok := trust.PublicKey(env.SigningKeyID)
	if !ok {
		return nil, fmt.Errorf("no trusted key with id=%q", env.SigningKeyID)
	}

	// Re-parse and re-canonicalize the manifest for verification.
	var raw any
	if err := json.Unmarshal(env.Manifest, &raw); err != nil {
		return nil, fmt.Errorf("manifest: parse: %w", err)
	}
	canon, err := CanonicalJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("manifest: canonicalize: %w", err)
	}

	// Check the manifest_hash commitment.
	sum := sha256.Sum256(canon)
	expected, ok := strings.CutPrefix(env.ManifestHash, "sha256:")
	if !ok {
		return nil, errors.New("manifest_hash: missing sha256: prefix")
	}
	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return nil, fmt.Errorf("manifest_hash: %w", err)
	}
	if !bytesEqual(sum[:], expectedBytes) {
		return nil, errors.New("manifest_hash: mismatch (canonicalization skew)")
	}

	// Verify signature over the canonical manifest bytes.
	sig, err := base64.StdEncoding.DecodeString(env.SignatureB64)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if !ed25519.Verify(pub, canon, sig) {
		return nil, errors.New("signature: verification failed")
	}

	// Parse into typed manifest last (signature already committed to bytes).
	var m Manifest
	if err := json.Unmarshal(env.Manifest, &m); err != nil {
		return nil, fmt.Errorf("manifest: decode: %w", err)
	}

	// Verify each policy document hash — defence in depth against a compromised
	// manifest builder that names a valid hash but embeds a divergent document.
	for _, p := range m.Policies {
		var pdoc any
		if err := json.Unmarshal(p.Document, &pdoc); err != nil {
			return nil, fmt.Errorf("policy %s@%s: parse: %w", p.PolicyID, p.Version, err)
		}
		pcanon, err := CanonicalJSON(pdoc)
		if err != nil {
			return nil, fmt.Errorf("policy %s@%s: canonicalize: %w", p.PolicyID, p.Version, err)
		}
		psum := sha256.Sum256(pcanon)
		expected, ok := strings.CutPrefix(p.DocumentHash, "sha256:")
		if !ok {
			return nil, fmt.Errorf("policy %s@%s: document_hash prefix", p.PolicyID, p.Version)
		}
		expectedBytes, err := hex.DecodeString(expected)
		if err != nil {
			return nil, fmt.Errorf("policy %s@%s: document_hash: %w", p.PolicyID, p.Version, err)
		}
		if !bytesEqual(psum[:], expectedBytes) {
			return nil, fmt.Errorf("policy %s@%s: document_hash mismatch", p.PolicyID, p.Version)
		}
	}

	// Detector supply-chain check (spec §6): every detector named by any guard
	// must appear in the manifest's detector table with a non-empty
	// image_digest. Unpinned detectors are refused — this is what makes bundle
	// installs a governed supply-chain event rather than a code deploy.
	if err := m.checkDetectorPins(); err != nil {
		return nil, err
	}

	return &m, nil
}

// checkDetectorPins ensures every guard.detector reference resolves to a
// detector row in the manifest that carries an image_digest.
//
// Exception: `secretscan@0.1.0` is the in-process detector — no OCI image
// exists, so we treat `image_digest="builtin"` as the pinned representation.
// This exception is explicit rather than open-ended so a mis-typed detector
// id can't silently escape the check.
func (m *Manifest) checkDetectorPins() error {
	byName := map[string]DetectorEntry{}
	for _, d := range m.Detectors {
		byName[d.DetectorID+"@"+d.Version] = d
	}
	referenced := map[string]bool{}
	for _, p := range m.Policies {
		var doc map[string]any
		if err := json.Unmarshal(p.Document, &doc); err != nil {
			continue
		}
		spec, _ := doc["spec"].(map[string]any)
		if spec == nil {
			continue
		}
		guards, _ := spec["guards"].([]any)
		for _, g := range guards {
			gm, _ := g.(map[string]any)
			if gm == nil {
				continue
			}
			det, _ := gm["detector"].(string)
			if det != "" {
				referenced[det] = true
			}
		}
	}
	for name := range referenced {
		d, ok := byName[name]
		if !ok {
			return fmt.Errorf("detector %s referenced by policy but missing from bundle manifest", name)
		}
		if d.ImageDigest == "" {
			return fmt.Errorf("detector %s: unpinned (empty image_digest) — spec §6 forbids", name)
		}
	}
	return nil
}

// AgeExceeded reports whether the bundle is older than max_age_hours (§3.2).
func (m *Manifest) AgeExceeded(now time.Time) bool {
	if m.MaxAgeHours <= 0 {
		return false
	}
	return now.Sub(m.CreatedAt) > time.Duration(m.MaxAgeHours)*time.Hour
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
