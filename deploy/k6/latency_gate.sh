#!/usr/bin/env bash
# CI latency-budget gate (spec §4.1).
#
# Fails the build if the gateway's `/v1/guard/check` p95 exceeds the target
# for the deterministic tier. Expects a running gateway with a policy that
# includes the deterministic guards (secrets + PII) — the compose profile
# already covers this once `harness/m1_demo.sh` has been run once.
#
# Usage:
#   ./deploy/k6/latency_gate.sh
#
# Env:
#   GUARDX_GATEWAY_URL       (default http://localhost:8081)
#   GUARDX_LATENCY_P95_MS    (default 30 — spec §4.1 deterministic-tier target)
#   GUARDX_APP               (default claims-bot)
set -euo pipefail

BASE="${GUARDX_GATEWAY_URL:-http://localhost:8081}"
TARGET="${GUARDX_LATENCY_P95_MS:-30}"
APP="${GUARDX_APP:-claims-bot}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "k6 not installed — install with 'brew install k6' or see https://k6.io/docs/getting-started/installation/"
  exit 2
fi

# Confirm the gateway is up before we burn a k6 minute.
if ! curl -fsS "$BASE/healthz" >/dev/null 2>&1; then
  echo "gateway not reachable at $BASE" >&2
  exit 3
fi

DIR="$(cd "$(dirname "$0")" && pwd)"
echo "» running k6 latency budget: target p95 < ${TARGET}ms"
GUARDX_GATEWAY_URL="$BASE" \
GUARDX_APP="$APP" \
GUARDX_LATENCY_P95_MS="$TARGET" \
  k6 run --quiet --summary-trend-stats='min,avg,med,p(95),max' "$DIR/latency_budgets.js"
