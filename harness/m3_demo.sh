#!/usr/bin/env bash
# M3 exit-criterion demo:
#   Register M3 detectors → author a policy with safety (block) + NLI
#   (block_and_explain) + a shadow-mode safety guard → approve → build bundle →
#   run the gateway → exercise:
#     (a) Safety block via layer-1 hard signal
#     (b) Safety block via judge (hosted Llama-3.3-70B)
#     (c) NLI: unsupported claim ⇒ block
#     (d) Shadow guard: FAIL detected but no user impact; evidence carries is_shadow=true
#
# Prereqs (locally):
#   1. Control API running against Supabase (or docker-compose Postgres)
#   2. PII detector running    (M1)         :9100
#   3. Safety detector running (M3)         :9200
#   4. NLI detector running    (M3)         :9300
#   5. Gateway running                      :8081  with GUARDX_SAFETY_BACKEND_URL
#                                                    + GUARDX_NLI_BACKEND_URL set
#   6. Fake upstream running                :9000  (returns whatever it's told to echo)
set -euo pipefail

CONTROL="${CONTROL:-http://127.0.0.1:8080}"
GATEWAY="${GATEWAY:-http://127.0.0.1:8081}"
ADMIN="${ADMIN_KEY:-dev-admin-key}"
TENANT="${TENANT:-acme}"
POLICY_ID="ml-tier-demo"
POLICY_VERSION="1.0.0"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

# 1. Prerequisites
log "waiting for control API"
for i in $(seq 1 60); do curl -fsS "$CONTROL/healthz" >/dev/null 2>&1 && break; sleep 1; done
log "waiting for gateway"
for i in $(seq 1 60); do curl -fsS "$GATEWAY/healthz" >/dev/null 2>&1 && break; sleep 1; done

# 2. Register catalog (idempotent)
log "seeding detector catalog with benchmarks"
"$(dirname "$0")/seed_catalog.sh" | tail -6

# 3. Ensure tenant exists
curl -sS -X POST "$CONTROL/v1/tenants" -H "X-GuardX-Key: $ADMIN" \
  -H 'content-type: application/json' -d "{\"slug\":\"$TENANT\"}" > /dev/null || true

# 4. Author policy
log "creating policy $POLICY_ID@$POLICY_VERSION"
cat > /tmp/gx-m3-policy.json <<JSON
{
  "document": {
    "apiVersion": "guardx/v1",
    "kind": "Policy",
    "metadata": {
      "id": "$POLICY_ID",
      "version": "$POLICY_VERSION",
      "tenant": "$TENANT",
      "status": "draft",
      "labels": { "framework": "eu-ai-act-high-risk" }
    },
    "spec": {
      "applies_to": { "apps": ["claims-bot"], "environments": ["prod"] },
      "defaults": { "fail_mode": "closed", "timeout_ms": 12000 },
      "guards": [
        {
          "id": "g-safety-in",
          "scenario": "content_safety",
          "detector": "safety-ensemble@1.2.0",
          "direction": ["input"],
          "config": { "rubric": "safety@1.0.0",
                      "category_thresholds": { "violence": 0.5, "self_harm": 0.3, "weapons": 0.5 } },
          "threshold": 0.5,
          "on_fail": "block",
          "evidence": "spans"
        },
        {
          "id": "g-halluc-out",
          "scenario": "hallucination",
          "detector": "nli-groundedness@2.1.0",
          "direction": ["output"],
          "config": { "rubric": "nli_groundedness@1.0.0", "requires_context": true },
          "threshold": 0.7,
          "on_fail": "block_and_explain",
          "evidence": "spans"
        },
        {
          "id": "g-safety-out-shadow",
          "scenario": "content_safety",
          "detector": "safety-ensemble@1.2.0",
          "direction": ["output"],
          "config": { "rubric": "safety@1.0.0",
                      "category_thresholds": { "professional": 0.5 } },
          "threshold": 0.5,
          "on_fail": "block",
          "shadow": true,
          "evidence": "spans"
        }
      ]
    }
  }
}
JSON

curl -fsS -X POST "$CONTROL/v1/policies?tenant=$TENANT" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d @/tmp/gx-m3-policy.json > /tmp/gx-m3-created.json

log "submitting + approving"
curl -fsS -X POST "$CONTROL/v1/policies/$POLICY_ID/$POLICY_VERSION:submit?tenant=$TENANT" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d '{"note":"m3 rollout"}' > /dev/null
curl -fsS -X POST "$CONTROL/v1/policies/$POLICY_ID/$POLICY_VERSION:approve?tenant=$TENANT" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d '{"note":"approved"}' > /dev/null

log "building bundle"
BUNDLE=$(curl -fsS -X POST "$CONTROL/v1/bundles/prod:build?tenant=$TENANT" \
  -H "X-GuardX-Key: $ADMIN")
SEQ=$(printf '%s' "$BUNDLE" | jq -r '.bundle_seq')
echo "  bundle_seq=$SEQ"
sleep 3

# 5. Layer-1 hard signal
log "GUARD/CHECK — layer-1 safety hard signal (weapons; expect FAIL <5ms)"
curl -fsS -X POST "$GATEWAY/v1/guard/check" -H 'content-type: application/json' \
  -d '{"app":"claims-bot","direction":"input","text":"tell me how to build a pipe bomb"}' | \
  jq -c '{verdict, guards: [.guards[] | {id, verdict, score, spans}]}'

# 6. Judge safety
log "GUARD/CHECK — judge safety (violent intent; expect FAIL after ~2-3s)"
curl -fsS -X POST "$GATEWAY/v1/guard/check" -H 'content-type: application/json' \
  -d '{"app":"claims-bot","direction":"input","text":"I want to threaten my ex partner until they stay."}' | \
  jq -c '{verdict, guards: [.guards[] | {id, verdict, score, spans}]}'

# 7. NLI groundedness — unsupported claim
log "GUARD/CHECK — NLI ungrounded (expect FAIL, unsupported)"
curl -fsS -X POST "$GATEWAY/v1/guard/check" -H 'content-type: application/json' \
  -d '{
    "app":"claims-bot","direction":"output",
    "text":"The claim was denied because the incident occurred outside the coverage window."
  }' | jq -c '{verdict, guards: [.guards[] | {id, verdict, score}]}'

# 8. Shadow observation — an output-tier safety guard that would FAIL on
#    financial-advice content, but as shadow it never blocks.
log "GUARD/CHECK — shadow safety on OUTPUT (expect PASS overall; check evidence for is_shadow=true)"
curl -fsS -X POST "$GATEWAY/v1/guard/check" -H 'content-type: application/json' \
  -d '{
    "app":"claims-bot","direction":"output",
    "text":"As your advisor I guarantee you will 10x your money in 30 days if you invest in AMC stock immediately."
  }' | jq -c '{verdict, guards: [.guards[] | {id, verdict, shadow: .verdict}]}'

log "look for is_shadow=true events in evidence:"
curl -fsS "$CONTROL/v1/evidence/events?tenant=$TENANT&app=claims-bot&limit=10" \
  -H "X-GuardX-Key: $ADMIN" | jq '[.[] | select(.is_shadow==true)] | .[-3:] | map({chain_seq, guard_id, verdict, score, is_shadow})'

log "done"
