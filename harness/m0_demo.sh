#!/usr/bin/env bash
# M0 exit-criterion demo:
#   Create tenant → draft policy → submit → approve → build bundle →
#   gateway pulls + hot-swaps → verify enforcement path uses policy@version.
#
# Prerequisites:
#   docker compose -f deploy/compose/docker-compose.yml up --build -d
#
# Usage:
#   ./harness/m0_demo.sh
set -euo pipefail

CONTROL="${CONTROL:-http://localhost:8080}"
GATEWAY="${GATEWAY:-http://localhost:8081}"
ADMIN_KEY="${ADMIN_KEY:-dev-admin-key}"
TENANT="${TENANT:-acme}"
POLICY_ID="pii-financial-services"
POLICY_VERSION="1.0.0"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

# 1. Wait for control API.
log "waiting for control API at ${CONTROL}"
for i in $(seq 1 60); do
  if curl -fsS "${CONTROL}/healthz" >/dev/null 2>&1; then
    echo "  control ready"; break
  fi
  sleep 1
done

log "waiting for gateway at ${GATEWAY}"
for i in $(seq 1 60); do
  if curl -fsS "${GATEWAY}/healthz" >/dev/null 2>&1; then
    echo "  gateway ready"; break
  fi
  sleep 1
done

# 2. Create tenant (idempotent).
log "creating tenant '${TENANT}' (409 = already exists — OK)"
curl -fsS -X POST "${CONTROL}/v1/tenants" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" \
  -H "content-type: application/json" \
  -d "{\"slug\":\"${TENANT}\"}" || true
echo

# 3. Create a draft policy.
log "creating draft policy ${POLICY_ID}@${POLICY_VERSION}"
cat > /tmp/guardx-m0-policy.json <<JSON
{
  "document": {
    "apiVersion": "guardx/v1",
    "kind": "Policy",
    "metadata": {
      "id": "${POLICY_ID}",
      "version": "${POLICY_VERSION}",
      "tenant": "${TENANT}",
      "status": "draft",
      "labels": { "framework": "GLBA,NYDFS-500" }
    },
    "spec": {
      "applies_to": { "apps": ["claims-bot"], "environments": ["prod"] },
      "defaults": { "fail_mode": "closed", "timeout_ms": 400 },
      "guards": [
        {
          "id": "g-pii-out",
          "scenario": "pii",
          "detector": "presidio-ensemble@1.4.0",
          "direction": ["output"],
          "config": { "entity_pack": "financial-us@2.1", "language": "en" },
          "threshold": 0.85,
          "on_fail": "redact",
          "evidence": "spans"
        }
      ]
    }
  }
}
JSON

curl -fsS -X POST "${CONTROL}/v1/policies?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" \
  -H "content-type: application/json" \
  -d @/tmp/guardx-m0-policy.json | tee /tmp/guardx-m0-created.json
echo

# 4. Submit → in_review.
log "submitting for review"
curl -fsS -X POST "${CONTROL}/v1/policies/${POLICY_ID}/${POLICY_VERSION}:submit?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" \
  -H "content-type: application/json" \
  -d '{"note":"initial submission"}'
echo

# 5. Approve (admin can approve own-policy in this dev script; SoD checked by role assignment in prod).
log "approving"
curl -fsS -X POST "${CONTROL}/v1/policies/${POLICY_ID}/${POLICY_VERSION}:approve?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" \
  -H "content-type: application/json" \
  -d '{"note":"looks good"}'
echo

# 6. Build a bundle for prod.
log "building bundle for env=prod"
BUNDLE=$(curl -fsS -X POST "${CONTROL}/v1/bundles/prod:build?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}")
echo "${BUNDLE}"
SEQ=$(printf '%s' "${BUNDLE}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bundle_seq"])')
echo "  bundle_seq=${SEQ}"

# 7. Wait for gateway to install the bundle.
log "waiting for gateway to install bundle seq ${SEQ}"
for i in $(seq 1 30); do
  if curl -fsS "${GATEWAY}/readyz" >/dev/null 2>&1; then
    echo "  gateway ready"; break
  fi
  sleep 1
done

# 8. Send a proxy call and a guard check — both should exercise the resolved
#    policy version, which the gateway logs as evidence events.
log "sending guarded chat completion"
curl -fsS -X POST "${GATEWAY}/v1/proxy/claims-bot/v1/chat/completions" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Hello from M0 demo"}]}'
echo

log "sending guard/check probe"
curl -fsS -X POST "${GATEWAY}/v1/guard/check" \
  -H "content-type: application/json" \
  -d '{"app":"claims-bot","direction":"output","text":"Hello from check"}'
echo

log "done. See gateway logs for decision events tagged with policy=${POLICY_ID}@${POLICY_VERSION} and bundle_seq=${SEQ}."
