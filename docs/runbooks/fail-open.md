# Runbook — Fail-open occurring

**Alert:** `GuardXFailOpenOccurring` (critical, security class)
**Signal:** `rate(guardx_guard_errors_total[5m]) > 0`

## What it means

Per spec §2 invariant I5, `fail_mode` is a per-guard policy property. Guards set to `fail_mode: open` will emit a `guard_error` event and **let traffic through** when their detector errors. That's a deliberate posture — used, e.g., for hallucination detectors where blocking every timeout would harm availability more than the risk warrants.

**But**: any period of fail-open on a **security-relevant** scenario (safety, secrets) is a documented compliance incident. This alert paginates security, not availability.

## Diagnose

1. Which guards are erroring?
   ```
   sum by (guard_id, scenario) (rate(guardx_guard_errors_total[5m]))
   ```
2. Which of those guards are `fail_mode: open`? Cross-check the currently installed bundle:
   ```sh
   kubectl -n guardx exec deploy/guardx-gateway -- \
     wget -qO- 'http://guardx-control:8080/v1/bundles/prod?tenant=acme&since=0' \
     -H "X-GuardX-Key: $ADMIN" | jq '.manifest.policies[].document.spec.guards[] | {id, fail_mode: (.fail_mode // "policy-default"), scenario}'
   ```
3. Establish the **duration** of the fail-open window. `guardx_bundle_installed_total` timestamps + the alert's `for:` window give the earliest/latest bounds.

## Fix

**Short-term:**
1. If the detector is recoverable → follow [provider-outage](provider-outage.md).
2. If the security posture matters more than availability → publish a policy version that flips the affected guards to `fail_mode: closed`. This will start blocking, but that's the point.

**Compliance:**
1. Record the incident. Include:
   - Affected `(tenant, app, guard_id)` tuples.
   - Fail-open start/end timestamps (from the alert's ranges).
   - Which requests were affected. The evidence store has every event tagged with the exact guard + verdict — use `SELECT count(*) FROM guard_decisions WHERE ... AND action_taken IS NULL` for the affected window.
2. Notify: compliance officer, security lead, and per your organisation's SIRP.
3. For SR 11-7 / SOC 2 / HIPAA: this belongs in the periodic incident summary.

## Prevent

- Audit the fail_mode of every guard on every policy promotion. The [console policy diff](../../console/src/pages/PolicyDetail.tsx) surfaces threshold + on_fail changes side-by-side.
- Use the shadow-mode pattern (§5.3) to observe how a proposed fail_mode change would behave under real traffic before promoting.
- If fail-open is a business-necessary configuration, wire a secondary detector (from another provider) into the same guard so both would have to fail simultaneously.
