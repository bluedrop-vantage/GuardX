#!/usr/bin/env bash
# M5 exit-criterion demo: automation plane.
#
# Exercises three surfaces end-to-end:
#   1. Feed ingestor: propose a monotonic-add of new secret patterns → server
#      auto-approves under rule AA-1 (feed + monotonic_add).
#   2. Feedback + auto-tuner: seed labeled feedback for a guard, run the
#      autotuner, verify it proposes a threshold move that requires human
#      approval (change_class=threshold_tune).
#   3. LLM synthesizer: run the CLI on a plain-text policy manual, verify it
#      produces a compiled guards[] draft and submits as a synthesizer
#      proposal in `draft` (human review required).
#
# Prereqs:
#   * Control API running (against Supabase or docker-compose)
#   * TOGETHER_AI_API_KEY set (for synthesizer)
#
# Usage:
#   ./harness/m5_demo.sh
set -euo pipefail

CONTROL="${CONTROL:-http://127.0.0.1:8080}"
ADMIN="${ADMIN_KEY:-dev-admin-key}"
SVC="${SERVICE_KEY:-dev-service-key}"
TENANT="${TENANT:-acme-m5}"
POLICY_ID="pii-financial-services"
POLICY_VERSION="1.0.0"
APP="claims-bot"
HERE=$(cd "$(dirname "$0")" && pwd)

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

log "wait for control API"
for i in $(seq 1 60); do curl -fsS "$CONTROL/healthz" >/dev/null 2>&1 && break; sleep 1; done

# Bootstrap tenant + approved policy (fresh for this run so the demo is
# self-contained).
log "bootstrap tenant + approved policy"
curl -sS -X POST "$CONTROL/v1/tenants" -H "X-GuardX-Key: $ADMIN" \
  -H 'content-type: application/json' -d "{\"slug\":\"$TENANT\"}" >/dev/null || true

cat > /tmp/gx-m5-policy.json <<JSON
{
  "document": {
    "apiVersion": "guardx/v1",
    "kind": "Policy",
    "metadata": {"id": "$POLICY_ID", "version": "$POLICY_VERSION", "tenant": "$TENANT", "status": "draft"},
    "spec": {
      "applies_to": {"apps": ["$APP"], "environments": ["prod"]},
      "defaults": {"fail_mode": "closed", "timeout_ms": 400},
      "guards": [
        {"id": "g-secrets-io", "scenario": "secrets",
         "detector": "secretscan@0.1.0", "direction": ["input","output"],
         "config": {}, "threshold": 0.9, "on_fail": "block", "evidence": "spans"},
        {"id": "g-pii-out", "scenario": "pii",
         "detector": "presidio-ensemble@1.4.0", "direction": ["output"],
         "config": {"entity_pack": "financial-us@2.1"},
         "threshold": 0.75, "on_fail": "redact", "evidence": "spans"}
      ]
    }
  }
}
JSON

# Try to create — if the id already exists (rerunning demo), reuse.
STATUS=$(curl -sf -X POST "$CONTROL/v1/policies?tenant=$TENANT" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d @/tmp/gx-m5-policy.json -o /tmp/gx-m5-policy-create.json -w '%{http_code}' || echo "000")
if [ "$STATUS" = "201" ]; then
  curl -sf -X POST "$CONTROL/v1/policies/$POLICY_ID/$POLICY_VERSION:submit?tenant=$TENANT" \
    -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' -d '{"note":"m5 seed"}' >/dev/null
  curl -sf -X POST "$CONTROL/v1/policies/$POLICY_ID/$POLICY_VERSION:approve?tenant=$TENANT" \
    -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' -d '{"note":"m5 seed"}' >/dev/null
  echo "  seed policy created + approved"
else
  echo "  policy exists — reusing"
fi

# =========================================================================
log "STAGE 1 — feed ingestor (monotonic_add → auto-approve)"
export GUARDX_CONTROL_BASE_URL="$CONTROL"
export GUARDX_SERVICE_KEY="$SVC"
. /Users/ajayrambhia/Downloads/GuardX/automation/.venv/bin/activate
python -m guardx_automation feed-gitleaks \
  --tenant "$TENANT" \
  --policy "$POLICY_ID" \
  --source "$HERE/fixtures/gitleaks_extra.json" | jq

log "list new versions of $POLICY_ID"
curl -sf "$CONTROL/v1/policies/$POLICY_ID?tenant=$TENANT" -H "X-GuardX-Key: $ADMIN" \
  | jq '.[] | {version, status, origin, auto_approval_rule: .document.metadata.auto_approval_rule}'

# =========================================================================
log "STAGE 2 — seed feedback for the pii guard, then run autotuner"

# Seed synthetic decision events + feedback so the autotuner has data.
python3 - <<PY
import http.client, json, random, os
control = os.environ["GUARDX_CONTROL_BASE_URL"].replace("http://", "").rstrip("/")
host, port = control.split(":") if ":" in control else (control, 80)
port = int(port)
random.seed(11)

def _post(path, headers, body):
    c = http.client.HTTPConnection(host, port)
    c.request("POST", path, json.dumps(body), headers)
    r = c.getresponse()
    d = r.read()
    assert r.status < 300, (r.status, d[:200])
    return json.loads(d)

svc = {"content-type": "application/json", "X-GuardX-Key": os.environ["GUARDX_SERVICE_KEY"]}
adm = {"content-type": "application/json", "X-GuardX-Key": os.environ.get("ADMIN_KEY", "dev-admin-key")}

# Ingest 120 decision events for guard g-pii-out with a mix of scores/labels.
events = []
for i in range(120):
    is_positive = i % 2 == 0
    score = round(random.uniform(0.72, 0.78) if not is_positive
                  else random.uniform(0.85, 0.99), 3)
    events.append({
        "event_id": f"m5-{i:04d}",
        "ts": f"2026-07-{15 + (i % 3):02d}T{10 + (i % 8):02d}:00:00Z",
        "tenant": "$TENANT", "app": "$APP", "env": "prod",
        "request_id": f"req-{i}",
        "policy": "$POLICY_ID@$POLICY_VERSION",
        "bundle_seq": 1,
        "guard_id": "g-pii-out", "scenario": "pii",
        "detector": "presidio-ensemble@1.4.0",
        "direction": "output",
        "verdict": "FAIL" if score >= 0.75 else "PASS",
        "score": score,
        "action_taken": "redact" if score >= 0.75 else None,
        "latency_ms": 12,
        "evidence_mode": "spans",
    })
r = _post("/v1/evidence/events", svc, {"events": events})
print(f"  seeded evidence: {r['accepted']} events")

# Label them: negatives (score ~0.72-0.78) are false positives; positives are true positives.
for i, e in enumerate(events):
    disp = "false_positive" if e["score"] < 0.80 else "true_positive"
    _post("/v1/feedback", adm, {
        "tenant": "$TENANT", "app": "$APP", "event_id": e["event_id"],
        "guard_id": "g-pii-out", "policy": "$POLICY_ID@$POLICY_VERSION",
        "source": "analyst", "disposition": disp,
        "note": None,
    })
print("  seeded feedback labels for 120 events")
PY

log "run autotuner"
python -m guardx_automation autotune \
  --tenant "$TENANT" --app "$APP" --policy "$POLICY_ID" \
  --min-labeled 20 --days-lookback 30 | jq

log "list versions of $POLICY_ID after autotuner"
curl -sf "$CONTROL/v1/policies/$POLICY_ID?tenant=$TENANT" -H "X-GuardX-Key: $ADMIN" \
  | jq '.[] | {version, status, origin}'

# =========================================================================
log "STAGE 3 — LLM synthesizer (draft, human review required)"
if [ -z "${TOGETHER_AI_API_KEY:-}" ]; then
  export TOGETHER_AI_API_KEY=$(grep TOGETHER_AI_API_KEY /Users/ajayrambhia/Downloads/GuardX/.env | cut -d= -f2 | tr -d "'\"")
fi
python -m guardx_automation synthesize \
  --tenant "$TENANT" \
  --policy synth-claims-bot \
  --apps "$APP" \
  --envs prod \
  --input "$HERE/fixtures/policy_doc.txt" | jq

log "list versions of synth-claims-bot"
curl -sf "$CONTROL/v1/policies/synth-claims-bot?tenant=$TENANT" -H "X-GuardX-Key: $ADMIN" \
  | jq '.[] | {version, status, origin}'

log "done — automation plane exercised end-to-end."
