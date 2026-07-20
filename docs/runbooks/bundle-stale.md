# Runbook — Bundle stale

**Alert:** `GuardXBundleStale` (warning) / `GuardXBundleAgeCritical` (critical)
**Signal:** `guardx_bundle_age_seconds > 259200` (72h) / `> 604800` (7d)

## What it means

The gateway is still serving policy from a bundle older than the spec §3.2 `max_age_hours` (default 72h). The gateway has already entered its per-guard **fail_mode posture** — that is:

- Guards with `fail_mode: closed` will now **block** on any detector error.
- Guards with `fail_mode: open` will **pass** on any detector error but emit `guard_error` events.

**Nothing was mutated silently** — the guarantee is that stale policy still gets applied, it just becomes less trustworthy over time. Regardless, this is a policy-drift signal that needs attention.

## Diagnose

1. Confirm the alert against the Grafana dashboard: **GuardX → Gateway → Bundle age (seconds)**.
2. Check the Control API's last bundle build for the tenant/env:
   ```sh
   curl -sSf "$CONTROL/v1/bundles/$ENV?tenant=$TENANT&since=0" -H "X-GuardX-Key: $ADMIN"
   ```
3. If the returned `bundle_seq` is **newer** than the gateway's `guardx_bundle_seq`, the gateway can't pull. Common causes:
   - Gateway → Control API network reachability (mesh / firewall / service mesh cert).
   - Bundle signature verification failing (usually a key rotation without gateway restart).
4. If the newest bundle in the registry itself is old:
   - No approved policy changes have happened. Investigate whether the **feed ingestor** and/or **autotuner** are alive (`kubectl -n guardx logs deploy/guardx-automation`).

## Fix

**A. Gateway can pull but is refusing bundles.** Restart the gateway pods to reset the last-known-good state:
```sh
kubectl -n guardx rollout restart deploy/guardx-gateway
```
Then watch `guardx_bundle_installed_total` for an increment.

**B. Signing key mismatch.** Publish the current signing pubkey to gateway env / secret and roll the deployment.

**C. Newest bundle in registry is actually old.** Trigger a fresh build:
```sh
curl -sSf -X POST "$CONTROL/v1/bundles/$ENV:build?tenant=$TENANT" -H "X-GuardX-Key: $ADMIN"
```
This picks up any new approved policies. If none exist, this is expected — the alert is a signal that nobody has updated policies in 72h, which is a governance question, not a technical one.

## Prevent

- Alert on `guardx_bundle_installed_total` rate == 0 over a rolling window in addition to age.
- Ensure the auto-tuner runs nightly per (tenant, app) and produces proposals for review.
- Track "human approval SLA" — draft proposals sitting >48h are effectively the reason for policy drift.
