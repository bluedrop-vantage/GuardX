#!/usr/bin/env bash
# Generate CycloneDX SBOMs for every GuardX artifact.
#
# Uses Syft — install with `brew install syft` or see https://github.com/anchore/syft.
# Output lands in ./sbom/<component>-<timestamp>.cdx.json for CI upload.
#
# Called during GA release CI. Local dev can use it too — it's fast (<10s).

set -euo pipefail

if ! command -v syft >/dev/null 2>&1; then
  echo "syft not installed — install with 'brew install syft'" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${SBOM_OUT_DIR:-$ROOT/sbom}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

emit() {
  local name="$1" path="$2"
  local out="$OUT/${name}-${TS}.cdx.json"
  echo "  → $out"
  syft scan --output cyclonedx-json --file "$out" "dir:$path"
}

log "Go module — gateway"
emit gateway "$ROOT/gateway"

log "Python — control API"
emit control "$ROOT/control"

log "Python — PII detector"
emit detector-pii "$ROOT/detectors/pii"

log "Python — safety detector"
emit detector-safety "$ROOT/detectors/safety"

log "Python — NLI detector"
emit detector-nli "$ROOT/detectors/nli"

log "Python — LLM judge shim"
emit detector-llm_judge "$ROOT/detectors/llm_judge"

log "Python — automation plane"
emit automation "$ROOT/automation"

log "Node — console"
emit console "$ROOT/console"

log "Aggregate: repo-wide SBOM"
syft scan --output cyclonedx-json --file "$OUT/guardx-${TS}.cdx.json" "dir:$ROOT"

log "wrote SBOMs to $OUT"
ls -la "$OUT"
