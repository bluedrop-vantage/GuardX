# Runbook — Evidence chain verification failed

**Signal:** `verify_chain` CLI returns non-zero, or the console **Evidence → Verify chain** banner reports `BROKEN`.

## What it means

The per-`(tenant, app)` hash chain of decision events is inconsistent. Concretely, one of:

1. **Sequence gap** — a `chain_seq` is missing.
2. **`prev_event_hash` mismatch** — the previous-hash pointer on some event does not match the previous event's `event_hash`.
3. **`event_hash` recomputation mismatch** — an event's fields were modified after ingest.

Every one of these is a **compliance-critical signal**. Do not clear it.

## Diagnose

1. Re-run the independent verifier from the harness — it recomputes hashes offline and does not trust the server:
   ```sh
   /path/to/verify_chain --base $CONTROL --api-key $ADMIN --tenant $TENANT --app $APP
   ```
   The failure message names the exact `chain_seq` that broke.
2. Look at the row directly in Postgres:
   ```sql
   SELECT event_id, chain_seq, verdict, event_hash, prev_event_hash
   FROM guard_decisions
   WHERE tenant = :tenant AND app = :app AND chain_seq BETWEEN :bad-2 AND :bad+2
   ORDER BY chain_seq;
   ```
3. Cross-check the row's `event_hash` against a fresh recompute in Python:
   ```py
   from guardx_control.evidence.chain import compute_event_hash
   compute_event_hash(row)   # should equal the stored value
   ```

## Fix

**This is not a fix-in-place bug.** The chain-break may indicate:

- **A. Legitimate DB tampering** — someone with direct DB access modified a row (spec §4.4 anticipates this: the chain is exactly the detection mechanism).
- **B. A canonicalisation bug** — a new field was added to `CHAIN_FIELDS` without a versioning story. Check the recent `control/guardx_control/evidence/chain.py` history.
- **C. Storage corruption** — bit rot / write reordering under crash.

In all cases:

1. **Do not delete or overwrite the affected rows.** The break itself is evidence.
2. **File a compliance incident.** For SOC 2 / HIPAA / SR 11-7 postures, this counts as a documented event.
3. Determine which `chain_anchors` cover the range. Anchors created before the tamper carry a signed head hash that lets an auditor prove the tamper post-dated the anchor. Anchors created after are worthless.
4. If the break was a canonicalisation bug (cause B), roll forward with a `CHAIN_FIELDS` bump and mark the old chain as retired. New events start a fresh chain. The old chain remains for auditor review.

## Prevent

- Restrict direct Postgres write access to the Control API service role. Use RLS + column-level GRANTs.
- Enable chain-anchor signing on a nightly cron so cover time windows are always <24h.
- Include the chain verifier CLI as a nightly CI job — earliest possible detection.
