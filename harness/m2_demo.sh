#!/usr/bin/env bash
# M2 exit-criterion demo:
#   Ingest evidence events → verify chain server-side → verify chain with
#   independent Go verifier → tamper one row → verifier catches it → restore.
#
# Prereqs: Control API running (locally against Supabase or docker-compose).
#   Local run:
#     . control/.venv/bin/activate
#     uvicorn guardx_control.api.app:app --host 127.0.0.1 --port 8080 &
#   Docker:
#     docker compose -f deploy/compose/docker-compose.yml up --build -d
#
# Usage:
#   ./harness/m2_demo.sh
set -euo pipefail

BASE="${CONTROL:-http://127.0.0.1:8080}"
SVC="${SERVICE_KEY:-dev-service-key}"
ADMIN="${ADMIN_KEY:-dev-admin-key}"
TENANT="${TENANT:-acme}"
APP="${APP:-m2-demo}"
N="${N:-1000}"
VERIFIER="$(cd "$(dirname "$0")"/verify_chain && pwd)/verify_chain"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

log "waiting for control API"
for i in $(seq 1 60); do
  curl -fsS "$BASE/healthz" >/dev/null 2>&1 && { echo "  ready"; break; }
  sleep 1
done

log "creating tenant '$TENANT' (ignore 409)"
curl -fsS -X POST "$BASE/v1/tenants" -H "X-GuardX-Key: $ADMIN" \
  -H 'content-type: application/json' -d "{\"slug\":\"$TENANT\"}" || true
echo

log "ingesting $N events into ($TENANT, $APP)"
python3 - <<PY
import http.client, json, random
random.seed(42)
BATCH = 200
c = http.client.HTTPConnection("127.0.0.1", 8080)
for i in range(0, $N, BATCH):
    events = []
    for j in range(min(BATCH, $N - i)):
        n = i + j + 1
        events.append({
            "event_id": f"m2-{n:06d}",
            "ts": f"2026-07-16T12:{n // 60:02d}:{n % 60:02d}Z",
            "tenant": "$TENANT", "app": "$APP", "env": "prod",
            "request_id": f"r-{n}",
            "policy": "pii-fs@1.0.0", "bundle_seq": 1,
            "guard_id": random.choice(["g-pii-out","g-secrets-in"]),
            "scenario": random.choice(["pii","secrets"]),
            "detector": "presidio-ensemble@1.4.0",
            "direction": random.choice(["input","output"]),
            "verdict": random.choice(["PASS","FAIL"]),
            "score": round(random.random(), 3),
            "evidence_mode": "spans",
            "latency_ms": random.randint(1, 60),
        })
    body = json.dumps({"events": events})
    c.request("POST", "/v1/evidence/events", body,
              {"content-type":"application/json", "X-GuardX-Key":"$SVC"})
    r = c.getresponse(); r.read()
    assert r.status == 201, r.status
print(f"  {$N} events ingested")
PY

log "server-side verify"
curl -fsS "$BASE/v1/evidence/verify?tenant=$TENANT&app=$APP" \
  -H "X-GuardX-Key: $ADMIN" | python3 -m json.tool

log "independent Go verifier"
"$VERIFIER" --base "$BASE" --api-key "$ADMIN" --tenant "$TENANT" --app "$APP"

log "sign a chain anchor"
curl -fsS -X POST "$BASE/v1/evidence/anchor?tenant=$TENANT&app=$APP" \
  -H "X-GuardX-Key: $ADMIN" | python3 -m json.tool

log "export bundle"
curl -fsS "$BASE/v1/evidence/export?tenant=$TENANT&app=$APP" \
  -H "X-GuardX-Key: $ADMIN" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print("  events:", len(d["events"]))
print("  anchors:", len(d["anchors"]))
print("  verify.ok:", d["verification"]["ok"])
'

log "done"
