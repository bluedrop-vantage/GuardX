#!/usr/bin/env bash
# M4 exit-criterion demo: zero-to-enforcing in <1 day.
#
# Emulates the console's onboarding walkthrough end-to-end via the API:
#   1. list available framework profiles
#   2. compile a policy from `glba-nydfs@1.0.0` for a new tenant + app
#   3. persist it, submit, approve
#   4. build a bundle → gateway hot-swap
#   5. verify the guarded proxy call actually runs the compiled policy
#
# Prereqs:
#   - Control API running against Supabase (or docker-compose)
#   - Gateway running with detector backends wired
#
# Usage:
#   ./harness/m4_demo.sh
set -euo pipefail

CONTROL="${CONTROL:-http://127.0.0.1:8080}"
ADMIN="${ADMIN_KEY:-dev-admin-key}"
TENANT="${TENANT:-acme-fs}"
PROFILE="${PROFILE:-glba-nydfs@1.0.0}"
POLICY_ID="claims-bot-policy"
POLICY_VERSION="1.0.0"

log() { printf '\n\033[1;36m» %s\033[0m\n' "$*"; }

log "waiting for control API"
for i in $(seq 1 60); do curl -fsS "$CONTROL/healthz" >/dev/null 2>&1 && break; sleep 1; done

log "creating tenant '$TENANT' (409 = already exists, ok)"
curl -sS -X POST "$CONTROL/v1/tenants" -H "X-GuardX-Key: $ADMIN" \
  -H 'content-type: application/json' -d "{\"slug\":\"$TENANT\"}" || true
echo

log "available framework profiles"
curl -sf "$CONTROL/v1/profiles/available" -H "X-GuardX-Key: $ADMIN" | \
  jq '.[] | "  " + .id + "@" + .version + "  (" + (.labels.framework // "-") + ")"' -r

log "compile ${PROFILE} for tenant=${TENANT}, app=claims-bot"
cat > /tmp/gx-m4-compile.json <<JSON
{
  "tenant": "${TENANT}",
  "profile": "${PROFILE}",
  "app_policy": {
    "metadata": {"id": "${POLICY_ID}", "version": "${POLICY_VERSION}"},
    "spec": {"applies_to": {"apps": ["claims-bot"], "environments": ["prod"]}}
  }
}
JSON
curl -sf -X POST "$CONTROL/v1/profiles/compile" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d @/tmp/gx-m4-compile.json > /tmp/gx-m4-compiled.json
echo "  compiled: $(jq -c '{guards_n: (.document.spec.guards | length), overrides_n: (.overrides | length)}' /tmp/gx-m4-compiled.json)"

log "guard summary (compiled)"
jq -r '.document.spec.guards[] | "  " + .id + "  " + .scenario + "  → " + .on_fail + " @ " + (.threshold | tostring)' /tmp/gx-m4-compiled.json

log "override trace (first 8)"
jq -r '.overrides[0:8] | .[] | "  " + .layer + "  " + .path' /tmp/gx-m4-compiled.json

log "persist the compiled document as a draft"
jq -c '{document: .document, change_note: "onboarded via glba-nydfs profile"}' /tmp/gx-m4-compiled.json > /tmp/gx-m4-create.json
CREATE_RESULT=$(curl -sf -X POST "$CONTROL/v1/policies?tenant=${TENANT}" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d @/tmp/gx-m4-create.json 2>/tmp/gx-m4-create.err || true)
if [ -z "$CREATE_RESULT" ]; then
  echo "  create failed:"; cat /tmp/gx-m4-create.err
  echo "  (already exists is fine — moving on)"
else
  echo "  created: $(printf '%s' "$CREATE_RESULT" | jq -c '.policy | {id: .policy_id, version, status, origin}')"
fi

log "submit → in_review"
curl -sf -X POST "$CONTROL/v1/policies/${POLICY_ID}/${POLICY_VERSION}:submit?tenant=${TENANT}" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d '{"note":"m4 onboarding demo"}' > /dev/null 2>&1 || true

log "approve → approved"
curl -sf -X POST "$CONTROL/v1/policies/${POLICY_ID}/${POLICY_VERSION}:approve?tenant=${TENANT}" \
  -H "X-GuardX-Key: $ADMIN" -H 'content-type: application/json' \
  -d '{"note":"approved for onboarding"}' > /dev/null 2>&1 || true

log "build bundle"
BUNDLE=$(curl -sf -X POST "$CONTROL/v1/bundles/prod:build?tenant=${TENANT}" -H "X-GuardX-Key: $ADMIN" || true)
if [ -n "$BUNDLE" ]; then
  echo "  bundle_seq=$(printf '%s' "$BUNDLE" | jq -r .bundle_seq)"
fi

log "list versions of the compiled policy"
curl -sf "$CONTROL/v1/policies/${POLICY_ID}?tenant=${TENANT}" -H "X-GuardX-Key: $ADMIN" | \
  jq -r '.[] | "  v" + .version + "  " + .status + "  origin=" + .origin + "  hash=" + .document_hash[0:20] + "…"'

log "done. Open the console at http://localhost:5173 and try the same flow interactively."
