# GuardX

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

Self-hostable, governed LLM guardrail platform. Enforces guardrails on LLM I/O across four scenarios — hallucination, PII, secrets/credentials, and content safety — with a centralized policy registry, cryptographically-signed bundles, evidence-grade audit trail, and automation plane.

See the full spec: [GuardX — Centralized LLM Guardrail Platform.md](GuardX%20%E2%80%94%20Centralized%20LLM%20Guardrail%20Platform.md).

## Milestone status

- [x] **M0 — Skeleton** — registry schema, Control API CRUD, JSON Schema + linter, Go gateway proxy with in-memory policy hot-swap.
- [x] **M1 — Deterministic tier** — in-process Go secrets detector, Python PII detector (regex + context scoring), redact/mask/block actions, parallel guard fan-out.
- [x] **M2 — Evidence** — Postgres-backed decision-event pipeline, per-`(tenant, app)` hash chain, signed daily anchors, HTTP emitter with disk-spool fallback, independent Go chain verifier.
- [x] **M3 — ML tier** — safety + NLI groundedness detectors via a **pluggable multi-provider LLM Judge** ([config/providers.yaml](config/providers.yaml)). Ships with Together + DeepInfra + OpenAI + Groq + local Ollama/vLLM/LM Studio profiles. Default safety routing: `safety_llamaguard@1.0.0` → DeepInfra Llama-Guard-4-12B (~350 ms). Tier-2 escalation, shadow mode.
- [x] **M4 — Profiles + console** — signed profile packs ([baseline](profiles/baseline@1.0.0.yaml), [hipaa](profiles/hipaa@1.0.0.yaml), [glba-nydfs](profiles/glba-nydfs@1.0.0.yaml)) with a deep-merge inheritance engine that records every override at leaf level. React + Vite + TS console at [console/](console/) with pages for Home, Onboarding walkthrough, Policies (list + side-by-side diff), Approval Queue (SoD-aware), Evidence (search + chain verify), Shadow Delta, and Detector Catalog. Zero-to-enforcing in one interactive flow.
- [x] **M5 — Automation** — feedback ingest (`POST /v1/feedback`), Gitleaks-style feed ingestor (auto-approved under `AA-1: feed + monotonic_add`), Wilson-CI auto-tuner (threshold proposals require human approval), LLM policy synthesizer (`origin=synthesizer`, always draft). APScheduler cron for the recurring jobs; Temporal deferred to when the synthesizer needs durable multi-step recovery. Every automation surface writes proposals only — invariant I3 holds by construction. See [harness/m5_demo.sh](harness/m5_demo.sh).
- [x] **GA hardening** — Prometheus `/metrics` on the gateway with per-guard latency histograms + bundle-age gauge; [Helm chart](deploy/helm/) with HA-shaped defaults (3× gateway, 2× per detector, PDB, ServiceMonitor); shipped [Grafana dashboard](deploy/helm/dashboards/gateway.json) and [alert rules](deploy/helm/alerts/guardx-alerts.yaml) covering spec §8 SLOs; four [operator runbooks](docs/runbooks/) linked from the alerts; [compliance mapping](docs/compliance/mapping.md) covering the spec §13 frameworks with artifact citations; k6 CI gate that fails on §4.1 latency regression; CycloneDX SBOM script; GitHub Actions CI; bundle verifier now refuses **unpinned detector versions** (spec §6); CORS locked down by default with an opt-in origin allowlist.

## Deferred claims

Three spec claims are **not** yet met by the default configuration:

1. **Spec §4.1 — Full tier-1 stack `<130 ms p95`.** Deterministic tier (secrets + PII) meets its `<30 ms` budget and is enforced by the k6 CI gate. ML tier via DeepInfra Llama-Guard-4-12B is ~350 ms — closer than Together (2–3 s) but still above target. Local vLLM behind a GPU would close the gap.
2. **Spec G5 — Fully self-hostable / air-gap capable.** Registry + gateway + evidence + deterministic detectors are all self-hostable. ML tier needs an operator to point the provider config at a local endpoint (Ollama / vLLM / LM Studio) — the `providers.yaml` shape already supports it, no code change required.
3. **FIPS 140 + external pen test.** Neither is a code artifact — FIPS 140 is a NIST-run validation program producing a certificate (~$50–150K lab engagement), and a pen test is a security-firm engagement producing an attestation letter. Scope + procurement path + pre-engagement hardening checklist documented at [docs/compliance/fips.md](docs/compliance/fips.md) and [docs/compliance/pen-test.md](docs/compliance/pen-test.md). Only worth doing when a specific buyer profile requires it (US federal / CMMC / SOC 2 Type 2 / Fortune 500 procurement).

### Closed

- **Spec §3.3 — Real OIDC** ✓ Provider-agnostic JWT verification with JWKS caching in the Control API ([oidc.py](control/guardx_control/api/oidc.py)). Console has an AuthContext + LoginPage supporting Supabase Auth (email/password with autoRefresh), manual JWT paste, and the legacy API-key path. `X-GuardX-Key` still works for automation-plane service tokens — Bearer wins when both are present. Role mapping via configurable dotted-path claim (default `app_metadata.guardx_role`). See [docs/runbooks/oidc-setup.md](docs/runbooks/oidc-setup.md) for Supabase / Keycloak / Auth0 recipes.

Change providers by editing [config/providers.yaml](config/providers.yaml). No code redeploy needed.

## Layout

```
gateway/        Go — data plane (proxy, in-process secrets, dispatcher, HTTP emitter)
control/        Python — FastAPI Control API + registry + evidence + profiles
detectors/
  pii/          Python — presidio-ensemble (regex + context)
  safety/       Python — llamaguard-shaped classifier via LLM judge
  nli/          Python — NLI groundedness (claim segmentation + judge)
  llm_judge/    Python — multi-provider rubric-driven judge
config/         providers.yaml — pluggable LLM backends (local + cloud)
console/        React + TS — admin console (Vite dev on :5173)
profiles/       signed framework profile packs (baseline, hipaa, glba-nydfs)
automation/     Python — feed ingestors + auto-tuner + LLM synthesizer + APScheduler runner
proto/          protobuf detector contract
schemas/        JSON Schemas: Policy, Bundle, Decision event
entity_packs/   versioned PII entity packs
harness/        golden sets, chain verifier, load, demo scripts
deploy/         helm/, compose/, k6/ (latency CI gate), sbom/
docs/           runbooks/, compliance/
```

## Quick start (local)

```sh
# Backend stack (Postgres + control + upstream + PII + gateway).
docker compose -f deploy/compose/docker-compose.yml up --build -d

# Admin console (separate terminal).
cd console && npm install && npm run dev
# → http://localhost:5173

# End-to-end demos by milestone.
./harness/m0_demo.sh   # policy → approve → bundle → gateway hot-swap
./harness/m1_demo.sh   # PII redact + secret block
./harness/m2_demo.sh   # evidence ingest, chain verify, tamper detection
./harness/m3_demo.sh   # safety + NLI + shadow mode (TOGETHER_AI_API_KEY needed)
./harness/m4_demo.sh   # onboarding: pick profile → compile → approve → bundle
./harness/m5_demo.sh   # feed ingest → autotuner → synthesizer (needs TOGETHER_AI_API_KEY)
```

Full env vars in [.env.example](.env.example).

## Production deploy

See **[docs/deployment/README.md](docs/deployment/README.md)** — operator walkthrough covering prereqs, signing-key handling, OIDC wiring, Helm install, first-boot checklist, upgrade + rollback, and multi-tenant shapes.

## Publishing / forking

If you're forking this repo or preparing your own copy for a public git remote, first read **[docs/deployment/pre-push-checklist.md](docs/deployment/pre-push-checklist.md)** — covers credential rotation, `.gitignore` sanity checks, contact-address swaps, and the first-push mechanics. Skipping any of it can leak keys or damage a first-impression.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Third-party attributions in [NOTICE](NOTICE). Security reports go through [SECURITY.md](SECURITY.md).

## Test suites

| Suite | Command |
| ----- | ----- |
| Go gateway | `cd gateway && go test ./...` |
| Python control API | `cd control && pytest` |
| PII detector | `cd detectors/pii && pytest` |
| LLM judge shim | `cd detectors/llm_judge && pytest` |
| Safety detector | `cd detectors/safety && pytest` |
| NLI groundedness | `cd detectors/nli && pytest` |
| Automation plane | `cd automation && pytest` |
| Console typecheck | `cd console && npm run typecheck` |
| Independent chain verifier | `harness/verify_chain/verify_chain --base $CONTROL --tenant $T --app $A` |
