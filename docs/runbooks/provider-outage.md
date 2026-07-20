# Runbook — LLM provider outage

**Signals:**
- `GuardXDetectorErrorSpike` firing on a scenario using an LLM-backed detector (safety, hallucination).
- `GuardXFailOpenOccurring` if the affected guards are `fail_mode: open`.
- Elevated `guardx_guard_latency_ms` p95 followed by timeouts.

## What it means

The judge provider named in `config/providers.yaml` — Together, DeepInfra, OpenAI, or a self-hosted vLLM/Ollama endpoint — is unreachable, rate-limiting, or returning 5xx.

- Guards with `fail_mode: closed` are **blocking** requests. This is the safer posture but appears as elevated `guardx_action_total{action="block"}`.
- Guards with `fail_mode: open` are **passing** requests without safety evaluation. Requests continue to flow but decisions are unguarded — treat as an active security incident.

## Diagnose

1. Confirm the failing detector via the Grafana dashboard **GuardX → Gateway → Detector errors** panel — the `scenario`/`guard_id` labels name what's failing.
2. Check the actual provider status:
   ```sh
   curl -sSf https://api.deepinfra.com/v1/openai/models -H "Authorization: Bearer $DEEPINFRA_API_KEY" | head
   curl -sSf https://api.together.xyz/v1/models     -H "Authorization: Bearer $TOGETHER_AI_API_KEY" | head
   ```
3. If provider is up but the detector is timing out, look at the detector pod logs:
   ```sh
   kubectl -n guardx logs deploy/guardx-detector-safety --tail=200
   ```

## Fix

**A. Provider outage / rate limit — hot-swap to backup provider.**
1. Edit `config/providers.yaml` (mounted via ConfigMap):
   ```yaml
   default: deepinfra    # was: together
   ```
   Or point the rubric's `model.provider` at another configured provider.
2. Roll the detector pods:
   ```sh
   kubectl -n guardx rollout restart deploy/guardx-detector-safety deploy/guardx-detector-nli
   ```
3. Verify errors clear on the dashboard.

**B. All providers down — stop bleeding.**
1. If `fail_mode: open` guards are letting unsafe traffic through, temporarily flip the guard's `fail_mode` via a **new** policy version (never edit approved policies in place):
   - Draft a version with `fail_mode: closed` on the affected guards.
   - Approve + build a fresh bundle.
   - Gateway hot-swaps in `~2s`.
2. Users will now see explicit block errors instead of unguarded responses.

**C. Rate limit only.**
1. Bump the detector's replica count temporarily so requests distribute across more connections:
   ```sh
   kubectl -n guardx scale deploy/guardx-detector-safety --replicas=6
   ```
2. Coordinate with the provider on quota increases.

## Prevent

- Configure **at least two providers** in `config/providers.yaml`. One can be the primary and one a warm-standby.
- Use `fail_mode: closed` on all safety guards unless there's a documented compensating control (spec §2 invariant I5 makes this a per-guard policy — audit trail matters).
- Include per-provider latency SLO alerts in the alerts config so degradation is caught before saturation.
