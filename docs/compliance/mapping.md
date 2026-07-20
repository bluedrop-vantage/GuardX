# Compliance mapping

Per spec §13, the following table maps regulatory-framework requirements to the specific GuardX controls that satisfy them. Every row cites the source-of-truth artifact so an auditor can verify without reading code.

| Framework | Requirement | GuardX control | Artifact |
| ----- | ----- | ----- | ----- |
| **NYDFS 500** | §500.03 written cybersecurity policies with periodic review | Policy registry with immutable versioning, SoD-enforced approval workflow, audit trail | [control/guardx_control/api/policies.py](../../control/guardx_control/api/policies.py), `policy_audit` table (migration 0001) |
| **NYDFS 500** | §500.06 audit trail of security events | Append-only decision events with per-`(tenant, app)` hash chain and signed daily anchors | [control/guardx_control/api/evidence.py](../../control/guardx_control/api/evidence.py), `guard_decisions` + `chain_anchors` tables |
| **NYDFS 500** | §500.17 incident notification | Prometheus alerts (`GuardXFailOpenOccurring` critical) + [fail-open runbook](../runbooks/fail-open.md) | [deploy/helm/alerts/guardx-alerts.yaml](../../deploy/helm/alerts/guardx-alerts.yaml) |
| **SOX ITGC** | Change management with approver segregation | Draft → in_review → approved lifecycle with author-cannot-approve-own enforcement | `_get_policy` + `approve_policy` in [policies.py](../../control/guardx_control/api/policies.py) |
| **SOX ITGC** | Access control with least privilege | Role-scoped API — Reviewer/Approver/Admin distinct, service tokens for automation | `require_role` in [auth.py](../../control/guardx_control/api/auth.py) |
| **SOX ITGC** | Immutable audit log | `policy_audit` table INSERT-only; no UPDATE code path exists | Migration 0001 + application-layer enforcement |
| **HIPAA §164.312(a)** | Access control | Per-tenant scoping enforced at API boundary + Postgres RLS (recommended) | `_get_tenant` guard in every route |
| **HIPAA §164.312(b)** | Audit controls | Decision-event stream captures every guard outcome with `policy_id@version` + `detector_id@version` (spec invariant I4) | [gateway/internal/proxy/proxy.go](../../gateway/internal/proxy/proxy.go) emit path |
| **HIPAA §164.312(c)** | Integrity | Hash-chain per-(tenant, app) + signed daily anchors; independent Go verifier | [harness/verify_chain/main.go](../../harness/verify_chain/main.go) |
| **HIPAA §164.312(d)** | Person or entity authentication | OIDC (staged) + service tokens; audit trail records subject on every state change | [auth.py](../../control/guardx_control/api/auth.py); real OIDC deferred to GA |
| **HIPAA §164.312(e)** | Transmission security | TLS between console/API/gateway/detectors; secrets never logged (`evidence_mode: spans` default on PII guards) | [minimizer.py](../../control/guardx_control/evidence/minimizer.py) |
| **HIPAA data minimization** | PHI never enters the evidence store as text | `evidence_mode: full_text` is refused by the linter for PII scenario; span-only capture enforced at emit-site + ingest-site | [linter.py](../../control/guardx_control/linter/linter.py) `_rule_full_text_evidence_under_pii` + [minimize.go](../../gateway/internal/evidence/minimize.go) |
| **SR 11-7** | Model risk management inventory | Detector catalog with pinned versions and published benchmark rows (precision/recall/latency); "no un-benchmarked detector is selectable" (spec §7) | `/v1/detectors` endpoint + [seed_catalog.sh](../../harness/seed_catalog.sh) |
| **SR 11-7** | Model documentation / prompts as artifact | LLM rubrics (safety, NLI, synthesizer) are versioned data files, not code | [detectors/llm_judge/rubrics/*.yaml](../../detectors/llm_judge/rubrics/) |
| **SR 11-7** | Independent validation / shadow evaluation | Shadow-mode guards + shadow-delta view; every evidence row carries `is_shadow` flag | [ShadowDeltaPage.tsx](../../console/src/pages/ShadowDeltaPage.tsx) + [tuner.py](../../automation/guardx_automation/autotuner/tuner.py) |
| **EU AI Act (Art. 12)** | Automatic logging | Decision events include: timestamp, tenant, app, policy@version, detector@version, direction, verdict, score, spans, latency — every field required by Art. 12(3) | `Event` struct in [emitter.go](../../gateway/internal/evidence/emitter.go) |
| **EU AI Act (Art. 14)** | Human oversight | Approval workflow requires human unless `origin=feed + change_class=monotonic_add`. Auto-approval rule id (`AA-1`) is stamped in `policy_audit`. Autotuner + synthesizer proposals **cannot** auto-approve. | Rule table in [policies.py](../../control/guardx_control/api/policies.py); see `_AUTO_APPROVAL_RULES` |
| **EU AI Act (Art. 15)** | Accuracy / robustness records | Detector benchmarks in the catalog; golden-set eval harness with tolerance-based promotion gate | [harness/eval.py](../../harness/eval.py) + [seed_catalog.sh](../../harness/seed_catalog.sh) |
| **PCI DSS 3.4** | PAN protection | `financial-us` entity pack matches PAN with **Luhn validation gate** (checksum required before span emission); `mask` action preserves last-4 only | [validators.py](../../detectors/pii/pii_detector/validators.py) + [action.go](../../gateway/internal/detector/action.go) |
| **PCI DSS 10** | Cardholder audit trail | Same decision-event pipeline as HIPAA/NYDFS; PAN never captured as text (spans only) | [minimizer.py](../../control/guardx_control/evidence/minimizer.py) |

## Cross-cutting

**Evidence integrity is the load-bearing control.** Every framework above depends on the hash chain and signed anchors. A `verify_chain` non-zero return is a **compliance-critical** signal; see the [chain-anchor-fail runbook](../runbooks/chain-anchor-fail.md).

**Approval-workflow integrity is the second load-bearing control.** Every framework above depends on the fact that the sole path from `draft` to `approved` runs through a human (or the narrow, audit-stamped `AA-1` auto-approval rule). Every state change is recorded in `policy_audit` with `actor`, `at`, `note`.

## What GuardX does *not* claim

- **SOC 2 Type 1/2 attestation.** Provides a control narrative and evidence artifacts; does not itself grant attestation — that requires an audit engagement.
- **FIPS 140-2/3 mode.** The signing library uses `cryptography` which can be FIPS-mode when the OS is FIPS-mode, but GuardX has not been validated with a FIPS test lab. See [deferrals](../../README.md#deferred-claims).
- **Air-gap for the ML tier** while any provider in `config/providers.yaml` points at a hosted SaaS. Point at a local `vllm` / `ollama` endpoint to remove the last SaaS dependency.
