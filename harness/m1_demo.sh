#!/usr/bin/env bash
# M1 exit-criterion demo:
#   Register detectors → author a policy with PII (redact) + Secrets (block)
#   guards → approve → build bundle → gateway hot-swaps → exercise:
#     (a) PII redaction on OUTPUT
#     (b) Secret blocking on INPUT
#
# Prerequisites:
#   docker compose -f deploy/compose/docker-compose.yml up --build -d
#
# Usage:
#   ./harness/m1_demo.sh
set -euo pipefail

CONTROL="${CONTROL:-http://localhost:8080}"
GATEWAY="${GATEWAY:-http://localhost:8081}"
ADMIN_KEY="${ADMIN_KEY:-dev-admin-key}"
TENANT="${TENANT:-acme}"
POLICY_ID="pii-financial-services"
POLICY_VERSION="1.0.0"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

# 1. Wait for services.
log "waiting for control API at ${CONTROL}"
for i in $(seq 1 60); do
  curl -fsS "${CONTROL}/healthz" >/dev/null 2>&1 && { echo "  control ready"; break; }
  sleep 1
done
log "waiting for gateway at ${GATEWAY}"
for i in $(seq 1 60); do
  curl -fsS "${GATEWAY}/healthz" >/dev/null 2>&1 && { echo "  gateway ready"; break; }
  sleep 1
done

# 2. Tenant + detector catalog.
log "creating tenant '${TENANT}'"
curl -sS -X POST "${CONTROL}/v1/tenants" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" -H "content-type: application/json" \
  -d "{\"slug\":\"${TENANT}\"}" || true
echo

log "registering detectors in catalog"
for det in \
  '{"detector_id":"secretscan","version":"0.1.0","scenario":"secrets","image_digest":"builtin","config_schema":{}}' \
  '{"detector_id":"presidio-ensemble","version":"1.4.0","scenario":"pii","image_digest":"builtin","config_schema":{}}'; do
  curl -sS -X POST "${CONTROL}/v1/detectors" \
    -H "X-GuardX-Key: ${ADMIN_KEY}" -H "content-type: application/json" \
    -d "${det}" || true
  echo
done

# 3. Author a policy with both guards.
log "creating policy ${POLICY_ID}@${POLICY_VERSION}"
cat > /tmp/guardx-m1-policy.json <<JSON
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
          "threshold": 0.7,
          "on_fail": "redact",
          "evidence": "spans"
        },
        {
          "id": "g-secrets-in",
          "scenario": "secrets",
          "detector": "secretscan@0.1.0",
          "direction": ["input"],
          "config": {},
          "threshold": 0.9,
          "on_fail": "block"
        }
      ]
    }
  }
}
JSON

curl -sS -X POST "${CONTROL}/v1/policies?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" -H "content-type: application/json" \
  -d @/tmp/guardx-m1-policy.json > /tmp/guardx-m1-created.json
echo "  created ${POLICY_ID}@${POLICY_VERSION}"

log "submitting + approving"
curl -sS -X POST "${CONTROL}/v1/policies/${POLICY_ID}/${POLICY_VERSION}:submit?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" -H "content-type: application/json" \
  -d '{"note":"m1 rollout"}' > /dev/null
curl -sS -X POST "${CONTROL}/v1/policies/${POLICY_ID}/${POLICY_VERSION}:approve?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}" -H "content-type: application/json" \
  -d '{"note":"approved"}' > /dev/null

log "building bundle"
BUNDLE=$(curl -sS -X POST "${CONTROL}/v1/bundles/prod:build?tenant=${TENANT}" \
  -H "X-GuardX-Key: ${ADMIN_KEY}")
SEQ=$(printf '%s' "${BUNDLE}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["bundle_seq"])')
echo "  bundle_seq=${SEQ}"

log "waiting for gateway to install bundle"
for i in $(seq 1 30); do
  curl -fsS "${GATEWAY}/readyz" >/dev/null 2>&1 && { echo "  ready"; break; }
  sleep 1
done
sleep 3  # let it swap the index

# 4a. Guard-check probe with an SSN in the OUTPUT direction — expect FAIL + redacted "Mutated".
log "GUARD/CHECK — PII (OUTPUT): should FAIL and offer a redacted payload"
curl -sS -X POST "${GATEWAY}/v1/guard/check" \
  -H "content-type: application/json" \
  -d '{"app":"claims-bot","direction":"output","text":"Confirmed SSN 123-45-6789 for the claim."}' | tee /tmp/guardx-m1-pii-check.json
echo

# 4b. Guard-check probe with a Stripe secret in INPUT — expect FAIL (block).
# Fake-value composed at runtime so the literal `sk_(live|test)_[24+ chars]`
# pattern never appears in tracked source (GitHub push-protection blocks it).
log "GUARD/CHECK — Secret (INPUT): should FAIL (block)"
FAKE_STRIPE="sk_${_MODE:-test}_ABCDEFGHIJKLMNOPQRSTUVWX"
curl -sS -X POST "${GATEWAY}/v1/guard/check" \
  -H "content-type: application/json" \
  -d "{\"app\":\"claims-bot\",\"direction\":\"input\",\"text\":\"here is my key: ${FAKE_STRIPE}\"}" | tee /tmp/guardx-m1-secret-check.json
echo

# 5. End-to-end proxy call — user prompts contain a secret → 403.
log "PROXY — user sends a secret in the prompt: expect 403 (blocked)"
set +e
curl -sSD - -o /tmp/guardx-m1-proxy-block.json -X POST "${GATEWAY}/v1/proxy/claims-bot/v1/chat/completions" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"my ghp_1234567890abcdefghij1234567890ABCDEF token"}]}' | head -1
set -e
cat /tmp/guardx-m1-proxy-block.json; echo

log "PROXY — clean prompt, upstream echoes an SSN: expect 200 with SSN redacted in response"
curl -sS -X POST "${GATEWAY}/v1/proxy/claims-bot/v1/chat/completions" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Please repeat: SSN 987-65-4321"}]}' | tee /tmp/guardx-m1-proxy-redact.json
echo

log "done. Gateway logs show decision events tagged policy=${POLICY_ID}@${POLICY_VERSION} bundle_seq=${SEQ} with spans."
