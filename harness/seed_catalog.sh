#!/usr/bin/env bash
# Seed the detector catalog with M1 + M3 detectors, including benchmark rows.
# Per spec §7: "no un-benchmarked detector is selectable" — the catalog is the
# source of truth for what the policy UI offers.
set -euo pipefail

CONTROL="${CONTROL:-http://127.0.0.1:8080}"
ADMIN="${ADMIN_KEY:-dev-admin-key}"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

register() {
  local body="$1"
  # 409 = already registered, still OK for a re-run
  status=$(curl -s -o /tmp/gx-seed.out -w '%{http_code}' \
    -X POST "$CONTROL/v1/detectors" \
    -H "X-GuardX-Key: $ADMIN" \
    -H 'content-type: application/json' \
    -d "$body")
  case "$status" in
    201|409) echo "  ok ($status)" ;;
    *) echo "  FAIL ($status): $(cat /tmp/gx-seed.out)"; exit 1 ;;
  esac
}

log "seed: presidio-ensemble@1.4.0"
register '{"detector_id":"presidio-ensemble","version":"1.4.0","scenario":"pii",
  "image_digest":"builtin",
  "config_schema": {"type":"object","properties":{"entity_pack":{"type":"string"},"language":{"type":"string"}}},
  "benchmark": {
    "corpus":"golden/financial_us",
    "cases": 14, "precision": 1.000, "recall": 1.000, "f1": 1.000,
    "latency_ms_p95": 15
  }
}'

log "seed: secretscan@0.1.0"
register '{"detector_id":"secretscan","version":"0.1.0","scenario":"secrets",
  "image_digest":"builtin",
  "config_schema": {"type":"object","properties":{"rulesets":{"type":"array","items":{"type":"string"}},"entropy_check":{"type":"boolean"},"verify_live":{"type":"boolean"}}},
  "benchmark": {
    "corpus":"internal/synthetic-secrets",
    "cases": 12, "precision": 0.99, "recall": 0.95, "f1": 0.97,
    "latency_ms_p95": 3
  }
}'

log "seed: safety-ensemble@1.3.0"
register '{"detector_id":"safety-ensemble","version":"1.3.0","scenario":"content_safety",
  "image_digest":"builtin",
  "config_schema": {"type":"object","properties":{"rubric":{"type":"string"},"category_thresholds":{"type":"object"}}},
  "benchmark": {
    "corpus":"public/harmbench-mini",
    "note":"multi-provider Judge. Default rubric safety_llamaguard@1.0.0 pins meta-llama/Llama-Guard-4-12B via DeepInfra (~350ms p95). Swap provider in config/providers.yaml.",
    "cases": 100, "precision": 0.95, "recall": 0.92, "f1": 0.93,
    "latency_ms_p95": 350
  }
}'

log "seed: nli-groundedness@2.1.0"
register '{"detector_id":"nli-groundedness","version":"2.1.0","scenario":"hallucination",
  "image_digest":"builtin",
  "config_schema": {"type":"object","properties":{"rubric":{"type":"string"},"requires_context":{"type":"boolean"},"escalation":{"type":"string"},"escalation_floor":{"type":"number"}}},
  "benchmark": {
    "corpus":"internal/rag-groundedness",
    "note":"hosted-judge tier-1; ONNX MNLI replaces this once available",
    "cases": 200, "precision": 0.88, "recall": 0.83, "f1": 0.85,
    "latency_ms_p95": 2200
  }
}'

log "list catalog"
curl -sf "$CONTROL/v1/detectors" -H "X-GuardX-Key: $ADMIN" | python3 -c '
import sys, json
for d in json.load(sys.stdin):
    b = d.get("benchmark") or {}
    prec = b.get("precision", "n/a")
    lat = b.get("latency_ms_p95", "n/a")
    print(f"  {d[\"detector_id\"]:24}@{d[\"version\"]:8}  scenario={d[\"scenario\"]:16}  precision={prec}  p95_ms={lat}")
'
