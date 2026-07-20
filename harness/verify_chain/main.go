// verify_chain — offline auditor for GuardX evidence chains.
//
// Reads events (either from the Control API or a JSONL export) and independently
// re-derives the per-(tenant, app) hash chain: seq contiguity, prev_event_hash
// linking, and event_hash correctness. Prints a report and exits non-zero on
// any inconsistency.
//
// Usage:
//   verify_chain --base http://localhost:8080 --tenant acme --app claims-bot \
//                --api-key dev-admin-key
//   verify_chain --file exported_events.jsonl
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// canonicalFields must match control/guardx_control/evidence/chain.py exactly.
var canonicalFields = []string{
	"event_id", "ts", "tenant", "app", "env", "chain_seq", "request_id",
	"policy", "bundle_seq", "guard_id", "scenario", "detector", "direction",
	"verdict", "score", "action_taken", "latency_ms", "evidence_mode", "spans",
	"text_hash", "prev_event_hash",
}

func main() {
	base := flag.String("base", "", "Control API base URL")
	apiKey := flag.String("api-key", "", "Control API key")
	tenant := flag.String("tenant", "", "tenant slug")
	app := flag.String("app", "", "app id")
	file := flag.String("file", "", "read events from JSONL file (skips API)")
	flag.Parse()

	var events []map[string]any
	var err error
	if *file != "" {
		events, err = loadFromFile(*file)
	} else if *base != "" && *tenant != "" && *app != "" {
		events, err = loadFromAPI(*base, *apiKey, *tenant, *app)
	} else {
		fmt.Fprintln(os.Stderr, "provide either --file or (--base --tenant --app)")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if len(events) == 0 {
		fmt.Println("no events to verify")
		return
	}

	sort.Slice(events, func(i, j int) bool {
		return numAsInt(events[i]["chain_seq"]) < numAsInt(events[j]["chain_seq"])
	})

	var prevHash string
	expectSeq := int64(1)
	for _, e := range events {
		seq := numAsInt(e["chain_seq"])
		if seq != expectSeq {
			fail(seq, fmt.Sprintf("seq gap: expected %d got %d", expectSeq, seq))
		}
		gotPrev, _ := e["prev_event_hash"].(string)
		if !nullableEqual(gotPrev, prevHash) {
			fail(seq, fmt.Sprintf("prev_event_hash mismatch: want=%q got=%q", prevHash, gotPrev))
		}
		want := computeHash(e)
		got, _ := e["event_hash"].(string)
		if want != got {
			fail(seq, fmt.Sprintf("event_hash recomputation mismatch: want=%s got=%s", want, got))
		}
		prevHash = got
		expectSeq++
	}
	fmt.Printf("chain OK: %d events, head=%s\n", len(events), truncate(prevHash, 40))
}

func fail(seq int64, msg string) {
	fmt.Fprintf(os.Stderr, "chain BROKEN at seq=%d: %s\n", seq, msg)
	os.Exit(1)
}

func loadFromAPI(base, apiKey, tenant, app string) ([]map[string]any, error) {
	u := fmt.Sprintf("%s/v1/evidence/events?tenant=%s&app=%s&limit=5000",
		base, url.QueryEscape(tenant), url.QueryEscape(app))
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("X-GuardX-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadFromFile(path string) ([]map[string]any, error) {
	fp, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	sc := bufio.NewScanner(fp)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []map[string]any
	for sc.Scan() {
		var e map[string]any
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// computeHash mirrors control/guardx_control/evidence/chain.py exactly.
func computeHash(e map[string]any) string {
	subset := make(map[string]any, len(canonicalFields))
	for _, k := range canonicalFields {
		subset[k] = e[k]
	}
	buf, _ := canonicalJSON(subset)
	sum := sha256.Sum256(buf)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// canonicalJSON is a minimal JCS-compatible encoder — same rules as
// gateway/internal/bundle/canonical.go.
func canonicalJSON(v any) ([]byte, error) {
	var sb strings.Builder
	if err := writeCanonical(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func writeCanonical(sb *strings.Builder, v any) error {
	switch x := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if x {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(x)
		sb.Write(b)
	case float64:
		if x == float64(int64(x)) && x >= -1e15 && x <= 1e15 {
			sb.WriteString(fmt.Sprintf("%d", int64(x)))
		} else {
			b, _ := json.Marshal(x)
			sb.Write(b)
		}
	case int:
		sb.WriteString(fmt.Sprintf("%d", x))
	case int64:
		sb.WriteString(fmt.Sprintf("%d", x))
	case []any:
		sb.WriteByte('[')
		for i, it := range x {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := writeCanonical(sb, it); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			b, _ := json.Marshal(k)
			sb.Write(b)
			sb.WriteByte(':')
			if err := writeCanonical(sb, x[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func numAsInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

func nullableEqual(a, b string) bool {
	if a == "" && b == "" {
		return true
	}
	return a == b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
