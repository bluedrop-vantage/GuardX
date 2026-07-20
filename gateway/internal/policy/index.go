// Package policy holds the in-memory policy index served to the request path.
//
// The index is a value swapped atomically each time a new verified bundle
// arrives (invariant I2: enforcement is stateless — any gateway can be killed
// and replaced, and the index rebuilds from the last-known-good bundle on
// start).
package policy

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/guardx/gateway/internal/bundle"
)

// Index is the read-optimized policy view queried per request.
type Index struct {
	BundleSeq int64
	CreatedAt time.Time
	// byAppEnv maps (app, environment) → resolved policies.
	byAppEnv map[appEnvKey][]*Resolved
	tenant   string
}

type appEnvKey struct{ app, env string }

// Resolved is a policy document plus decoded shape for hot-path use.
type Resolved struct {
	PolicyID string
	Version  string
	Document map[string]any
	Guards   []Guard
	FailMode string
	TimeoutMs int
}

// Guard is the runtime shape of a spec.guards[*] entry.
type Guard struct {
	ID         string
	Scenario   string
	Detector   string
	Direction  []string
	Threshold  any
	OnFail     string
	Config     map[string]any
	Evidence   string
	FailMode   string
	Shadow     bool
}

// Snapshot is the atomic pointer holder.
type Snapshot struct {
	current atomic.Pointer[Index]
}

func NewSnapshot() *Snapshot { return &Snapshot{} }

func (s *Snapshot) Load() *Index { return s.current.Load() }

func (s *Snapshot) Store(idx *Index) { s.current.Store(idx) }

// Build converts a verified manifest into a request-path index.
func Build(m *bundle.Manifest) (*Index, error) {
	if m == nil {
		return nil, fmt.Errorf("nil manifest")
	}
	idx := &Index{
		BundleSeq: m.BundleSeq,
		CreatedAt: m.CreatedAt,
		tenant:    m.Tenant,
		byAppEnv:  map[appEnvKey][]*Resolved{},
	}

	for _, p := range m.Policies {
		var doc map[string]any
		if err := json.Unmarshal(p.Document, &doc); err != nil {
			return nil, fmt.Errorf("policy %s@%s: parse: %w", p.PolicyID, p.Version, err)
		}
		spec, _ := doc["spec"].(map[string]any)
		if spec == nil {
			continue
		}
		applies, _ := spec["applies_to"].(map[string]any)
		if applies == nil {
			continue
		}
		defaults, _ := spec["defaults"].(map[string]any)
		failMode := ""
		timeoutMs := 0
		if defaults != nil {
			if v, ok := defaults["fail_mode"].(string); ok {
				failMode = v
			}
			if v, ok := defaults["timeout_ms"].(float64); ok {
				timeoutMs = int(v)
			}
		}

		resolved := &Resolved{
			PolicyID:  p.PolicyID,
			Version:   p.Version,
			Document:  doc,
			FailMode:  failMode,
			TimeoutMs: timeoutMs,
			Guards:    buildGuards(spec),
		}

		apps, _ := applies["apps"].([]any)
		envs, _ := applies["environments"].([]any)
		for _, a := range apps {
			appStr, _ := a.(string)
			for _, e := range envs {
				envStr, _ := e.(string)
				key := appEnvKey{app: appStr, env: envStr}
				idx.byAppEnv[key] = append(idx.byAppEnv[key], resolved)
			}
		}
	}
	return idx, nil
}

func buildGuards(spec map[string]any) []Guard {
	raw, _ := spec["guards"].([]any)
	out := make([]Guard, 0, len(raw))
	for _, r := range raw {
		g, _ := r.(map[string]any)
		if g == nil {
			continue
		}
		dirs, _ := g["direction"].([]any)
		directions := make([]string, 0, len(dirs))
		for _, d := range dirs {
			if s, ok := d.(string); ok {
				directions = append(directions, s)
			}
		}
		cfg, _ := g["config"].(map[string]any)
		out = append(out, Guard{
			ID:        stringOr(g, "id", ""),
			Scenario:  stringOr(g, "scenario", ""),
			Detector:  stringOr(g, "detector", ""),
			Direction: directions,
			Threshold: g["threshold"],
			OnFail:    stringOr(g, "on_fail", ""),
			Config:    cfg,
			Evidence:  stringOr(g, "evidence", ""),
			FailMode:  stringOr(g, "fail_mode", ""),
			Shadow:    boolOr(g, "shadow", false),
		})
	}
	return out
}

func stringOr(m map[string]any, k, def string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return def
}

func boolOr(m map[string]any, k string, def bool) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return def
}

// Resolve returns policies to enforce for (app, environment).
func (i *Index) Resolve(app, env string) []*Resolved {
	if i == nil {
		return nil
	}
	return i.byAppEnv[appEnvKey{app, env}]
}

// Tenant returns the tenant slug of the loaded bundle.
func (i *Index) Tenant() string { return i.tenant }
