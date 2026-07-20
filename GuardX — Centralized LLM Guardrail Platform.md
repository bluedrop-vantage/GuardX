# **GuardX — Centralized LLM Guardrail Platform**

## **Product & Engineering Specification**

|  |  |
| ----- | ----- |
| **Document** | GuardX Product Specification |
| **Version** | 1.0 (Draft for engineering review) |
| **Date** | July 16, 2026 |
| **Status** | Ready for build — Milestone 0 |
| **Audience** | Engineering, Product, Compliance |

---

## **1\. Overview**

### **1.1 Problem statement**

Existing open-source guardrail frameworks (Guardrails AI, NeMo Guardrails, LLM Guard) treat guard rules as application code: scattered across Python files, XML specs, and Pydantic models, with no central store, no versioned policy registry, no approval workflow, and no runtime record of which rule version evaluated which output. For regulated enterprises this is disqualifying — validation without governance is not a control.

### **1.2 Product summary**

GuardX is a self-hostable platform that enforces guardrails on LLM inputs and outputs across four scenario families — **hallucination, PII, secrets/credentials, and content safety** — with three differentiators:

1. **Centralized, governed policy store.** Guard rules are versioned, signed, approved data — not code. One registry serves every application, environment, and team.  
2. **Domain-configurable by design.** Industry profile packs (HIPAA, GLBA, NYDFS 500, EU AI Act) select entity sets, thresholds, and fail actions. Customers inherit a defensible posture on day one.  
3. **Self-maintaining.** External feeds, an LLM policy synthesizer, and a feedback-driven auto-tuner keep policies current with minimal human intervention — while every automated change enters as a reviewable proposal with full provenance.

### **1.3 Goals**

* G1: Single source of truth for all guard policies, with immutable versioning and cryptographic signing.  
* G2: Sub-50ms p95 added latency for the deterministic tier (PII regex/NER, secrets); sub-300ms p95 for the ML tier on standard chat payloads (≤4K tokens).  
* G3: Compliance-grade evidence: every guard decision reconstructible with policy version, detector version, spans, scores, and action taken.  
* G4: Zero-to-enforcing in under one day for a new tenant via industry profiles \+ LLM policy synthesis from customer documents.  
* G5: Fully self-hostable (air-gap capable); no mandatory external SaaS dependencies.

### **1.4 Non-goals (v1)**

* NG1: Multi-turn conversation-level guards (single-call scope in v1; conversation context is a v2 roadmap item — see §14).  
* NG2: Multimodal (image/audio) validation.  
* NG3: Agentic tool-call authorization (v2).  
* NG4: Model fine-tuning or training-time safety.  
* NG5: Replacing provider-native structured output (we validate, we do not generate).

### **1.5 Personas**

| Persona | Needs |
| ----- | ----- |
| **Compliance officer** | Author/approve policies without writing code; export audit evidence; map guards to frameworks |
| **Platform engineer** | Deploy gateway; integrate via SDK/proxy; monitor latency and block rates |
| **Application developer** | Attach a named policy to an app with one config line; debug why an output was blocked |
| **Security analyst** | Review flagged events; tune thresholds; ingest threat feeds |
| **Auditor (external)** | Receive evidence packages proving controls were in force for a time range |

---

## **2\. System architecture**

Three planes, cleanly separated (OPA-style control/data plane split):

```
┌─────────────────────────────────────────────────────────────┐
│ POLICY CONTROL PLANE                                        │
│  Policy Registry · Industry Profiles · Approval Workflow    │
│  (Postgres + Control API)                                   │
└───────────────┬─────────────────────────────▲───────────────┘
                │ signed policy bundles       │ proposals
                ▼                             │
┌─────────────────────────────────────────────┼───────────────┐
│ ENFORCEMENT PLANE (data plane)              │               │
│  Guard Gateway · Detector Services · Evidence Store         │
│  (Go gateway + gRPC detectors + Kafka→ClickHouse/S3)        │
└───────────────┬─────────────────────────────┼───────────────┘
                │ decision telemetry          │
                ▼                             │
┌─────────────────────────────────────────────┴───────────────┐
│ AUTOMATION PLANE                                            │
│  Feed Ingestors · LLM Policy Synthesizer · Auto-Tuner       │
│  (Python workers on Temporal)                               │
└─────────────────────────────────────────────────────────────┘
```

**Key invariants:**

* I1: Enforcement points never accept a policy that is unsigned, expired, or not `approved`.  
* I2: Enforcement is stateless — all state lives in the registry (config) and evidence store (history). Any gateway/detector instance can be killed and replaced.  
* I3: Automation writes **proposals only**; the sole path to `approved` is the approval workflow (human, or auto-approval rules for monotonic-safe changes).  
* I4: Every decision event records `policy_id@version` and `detector_id@version`.  
* I5: Fail behavior (open vs. closed) is a per-guard policy property, never a hardcoded default.

---

## **3\. Policy control plane**

### **3.1 Policy data model**

A **Policy** is a named, versioned document composed of **Guards**. A Guard binds a **Scenario** (pii | secrets | hallucination | content\_safety) to a **Detector** (pinned version) with configuration, direction, threshold, and an on-fail action. Policies inherit from **Profiles** (org baseline → industry profile → app policy) via deep-merge with override tracking.

#### **Policy document schema (canonical YAML; stored as JSONB)**

```
apiVersion: guardx/v1
kind: Policy
metadata:
  id: pii-financial-services          # immutable slug, unique per tenant
  version: 3.2.0                       # semver; every change = new version
  tenant: acme-insurance
  status: approved                     # draft | in_review | approved | deprecated | revoked
  profile: glba-nydfs                  # inherited base profile (optional)
  labels: { framework: "GLBA,NYDFS-500", owner: compliance }
  created_by: j.smith@acme.com
  approved_by: c.officer@acme.com
  approved_at: 2026-07-01T14:22:05Z
  change_note: "Raised PII threshold per FP review batch 2026-06"
spec:
  applies_to:                          # binding targets
    apps: [claims-bot, underwriting-assistant]
    environments: [prod]
  defaults:
    fail_mode: closed                  # closed = block on detector error; open = pass + flag
    timeout_ms: 400                    # end-to-end guard budget for this policy
  guards:
    - id: g-pii-out
      scenario: pii
      detector: presidio-ensemble@1.4.0
      direction: [input, output]
      config:
        entity_pack: financial-us@2.1  # SSN, ACCOUNT_NUMBER, ROUTING_NUMBER, CUSIP...
        entities_extra: [ACME_POLICY_NUMBER]
        language: en
      threshold: 0.85
      on_fail: redact                  # block | redact | rewrite | flag | reask
      evidence: spans                  # none | spans | full_text (data-minimization control)
    - id: g-secrets-out
      scenario: secrets
      detector: secretscan@2.0.1
      direction: [output]
      config:
        rulesets: [gitleaks-core@8.x, acme-internal@1.0]
        entropy_check: true
        verify_live: false             # never verify against live services in prod
      threshold: 1.0                   # deterministic
      on_fail: block
    - id: g-halluc-out
      scenario: hallucination
      detector: nli-groundedness@2.1.0
      direction: [output]
      config:
        requires_context: true         # request must carry RAG context or guard flags
        escalation: llm-judge@1.3.0    # tier-2 only for scores in [0.5, threshold)
        citation_required: true
      threshold: 0.70
      on_fail: block_and_explain
    - id: g-safety-io
      scenario: content_safety
      detector: safety-ensemble@1.2.0
      direction: [input, output]
      config:
        taxonomy: llamaguard-v3
        category_thresholds: { violence: 0.5, self_harm: 0.3, sexual: 0.4 }
        custom_rules_pack: acme-brand@1.2   # LLM-judge bespoke rules
      threshold: default
      on_fail: block
```

#### **Registry database (PostgreSQL DDL, abridged)**

```sql
CREATE TABLE tenants (
  id UUID PRIMARY KEY, slug TEXT UNIQUE NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies (
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  policy_id TEXT NOT NULL,               -- slug
  version TEXT NOT NULL,                 -- semver
  status TEXT NOT NULL CHECK (status IN ('draft','in_review','approved','deprecated','revoked')),
  document JSONB NOT NULL,               -- full canonical policy
  document_hash BYTEA NOT NULL,          -- sha256 of canonical JSON
  parent_version TEXT,                   -- lineage
  origin TEXT NOT NULL CHECK (origin IN ('manual','feed','synthesizer','autotuner')),
  origin_ref JSONB,                      -- provenance: feed id, source doc para, feedback batch
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_by TEXT, approved_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, policy_id, version)
);
-- Rows are INSERT-only. Status transitions append an audit row; no UPDATE of document.

CREATE TABLE policy_audit (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL, policy_id TEXT NOT NULL, version TEXT NOT NULL,
  action TEXT NOT NULL,                  -- created | submitted | approved | rejected | promoted | revoked
  actor TEXT NOT NULL, note TEXT, at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bundles (
  tenant_id UUID NOT NULL, environment TEXT NOT NULL,
  bundle_seq BIGINT NOT NULL,            -- monotonic
  manifest JSONB NOT NULL,               -- {policy_id: version} map + detector pins
  signature BYTEA NOT NULL,              -- Ed25519 over manifest hash
  signing_key_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, environment, bundle_seq)
);

CREATE TABLE detectors (
  detector_id TEXT NOT NULL, version TEXT NOT NULL,
  scenario TEXT NOT NULL,
  image_digest TEXT NOT NULL,            -- OCI digest of detector service
  config_schema JSONB NOT NULL,          -- JSON Schema validating guard.config
  benchmark JSONB,                       -- accuracy metrics per eval suite
  PRIMARY KEY (detector_id, version)
);

CREATE TABLE profiles (
  profile_id TEXT NOT NULL, version TEXT NOT NULL,
  document JSONB NOT NULL, signature BYTEA NOT NULL,
  PRIMARY KEY (profile_id, version)
);
```

### **3.2 Versioning, signing, distribution**

* **Immutability.** Policy documents are append-only. Editing creates version N+1 in `draft`. Rollback \= re-promote an older approved version into a new bundle (recorded in audit).  
* **Signing.** On approval, the Control API canonicalizes the JSON (RFC 8785), hashes (SHA-256), and signs with an Ed25519 key held in KMS/HSM (or SoftHSM for air-gap). Bundles (the per-environment manifest of approved policy versions \+ detector image digests) are signed the same way.  
* **Distribution.** Gateways long-poll `GET /v1/bundles/{env}?since={seq}` (or subscribe via Redis pub/sub for push). On receipt: verify signature → verify each policy hash → hot-swap the in-memory policy index atomically. A gateway that cannot verify keeps its last-known-good bundle and raises an alert. Bundles are also mirrored to object storage so gateways can cold-start without the Control API being up.  
* **Staleness guard.** Bundles carry `max_age_hours` (default 72). A gateway serving a bundle past max age enters per-policy `fail_mode` posture and alerts.

### **3.3 Approval workflow & RBAC**

Roles (per tenant): `viewer`, `author`, `reviewer`, `approver`, `admin`. Separation of duty: an author cannot approve their own version; approver role is grantable only by admin.

State machine: `draft → in_review → approved → (deprecated | revoked)`. `revoked` triggers immediate bundle rebuild removing the policy.

**Auto-approval rules** (configurable, default conservative): only proposals with `origin=feed` AND change class `monotonic_add` (new detection patterns, no threshold/action changes) may skip human review; everything from the synthesizer or auto-tuner requires a human approver. Every auto-approval is stamped in `policy_audit` with the matching rule ID.

### **3.4 Industry profile packs**

A profile is a signed, versioned policy fragment shipped by Ajay (or authored by the tenant) that sets scenario defaults for a regulatory context. v1 ships:

| Profile | Contents (summary) |
| ----- | ----- |
| `baseline` | Secrets block-on-detect; PII flag; safety llamaguard defaults; hallucination flag-only |
| `hipaa` | PHI entity pack (MRN, NPI, DEA, DOB+name combos); redact; evidence=spans only; strict retention |
| `glba-nydfs` | Financial entity pack; redact \+ block on SSN/account combos; hallucination threshold 0.8 for advice-class apps |
| `eu-ai-act-high-risk` | Full evidence, human-review queue on all blocks, mandatory citation on generated claims |
| `pci` | PAN detection with Luhn validation; block; truncated-PAN-only evidence |

Inheritance: `baseline ⊕ profile ⊕ app-policy`, deep-merged; every overridden field records `overrides: profile-field` so auditors can see divergence from the framework default.

### **3.5 Control API (REST, OpenAPI 3.1)**

| Method & path | Purpose |
| ----- | ----- |
| `POST /v1/policies` | Create draft (validates against JSON Schema \+ detector config schemas) |
| `GET /v1/policies/{id}` / `?version=` | Fetch; `diff=v1..v2` returns structured diff |
| `POST /v1/policies/{id}/{ver}:submit` | draft → in\_review |
| `POST /v1/policies/{id}/{ver}:approve` / `:reject` | Reviewer/approver actions (note required) |
| `POST /v1/bundles/{env}:build` | Compose \+ sign new bundle for environment |
| `GET /v1/bundles/{env}?since={seq}` | Gateway pull (long-poll) |
| `GET /v1/profiles`, `POST /v1/profiles` | Profile pack management |
| `GET /v1/detectors` | Detector catalog with pinned versions \+ benchmarks |
| `POST /v1/proposals` | Automation plane submits proposals (scoped service token) |
| `GET /v1/evidence:export?from=&to=&app=` | Auditor evidence package (async job → signed archive) |

AuthN: OIDC (human) \+ mTLS/service tokens (machine). AuthZ: role checks \+ tenant isolation enforced at the API layer and by Postgres RLS.

---

## **4\. Enforcement plane**

### **4.1 Guard Gateway**

The gateway is the single enforcement point. Three integration modes, one codebase:

1. **Reverse proxy (recommended).** Applications point their OpenAI/Anthropic-compatible base URL at the gateway; the gateway validates input, forwards upstream, validates output, applies the on-fail action, returns. Zero application code change.  
2. **Sidecar / ext\_proc.** Same binary deployed per-pod, or as an Envoy `ext_proc` filter for service-mesh shops.  
3. **SDK check mode.** `POST /v1/guard/check` for applications that want validate-only semantics (they call the LLM themselves). SDKs (Python/TS) are thin HTTP wrappers — no validation logic client-side, ever.

#### **Request flow (proxy mode)**

```
client → [gateway]
  1. resolve policy: (tenant, app, environment) → policy@version from in-memory index
  2. INPUT phase: dispatch input-direction guards to detectors (parallel fan-out, gRPC)
  3. gate: any hard-fail (block) → 403 with structured GuardError; redact/rewrite → mutate
  4. forward to upstream LLM (streaming or unary)
  5. OUTPUT phase:
     - unary: validate complete response (parallel fan-out)
     - streaming: chunked validation (see 4.2)
  6. apply on_fail actions; emit decision event (async, fire-and-forget to log pipeline)
  7. respond
```

#### **Latency budget (p95 targets, ≤4K-token payload)**

| Stage | Budget |
| ----- | ----- |
| Policy resolution (in-memory) | \< 0.1 ms |
| Secrets detector (regex+entropy, Go) | \< 5 ms |
| PII detector (regex \+ ONNX NER) | \< 25 ms |
| Content safety (small classifier, ONNX/GPU) | \< 40 ms |
| Hallucination tier-1 (NLI, ONNX/GPU) | \< 80 ms |
| Hallucination tier-2 (LLM judge, borderline only) | \< 800 ms (async-eligible) |
| Gateway overhead (routing, fan-out, action) | \< 3 ms |
| **Deterministic-tier total (secrets+PII)** | **\< 30 ms** |
| **Full stack, all four scenarios, tier-1 only** | **\< 130 ms** |

Guards within a phase run in **parallel**; the phase completes at max(guard latencies), not sum. Tier-2 escalations may run in `async` mode per policy: response is released with `flag`, judge verdict lands in the evidence store and can trigger retro-actions (alert, takedown webhook).

#### **Fail modes & resilience**

* Per-guard `fail_mode`: `closed` (detector timeout/error ⇒ treat as fail, apply on\_fail) or `open` (pass \+ emit `guard_error` event). Regulated defaults: secrets/PII closed, hallucination open.  
* Circuit breaker per detector backend (5xx/timeout rate \> threshold ⇒ open for cool-down; behavior per fail\_mode).  
* Gateway is stateless; horizontal scale behind L4 LB; policy index rebuilt from last-known-good bundle on start.

### **4.2 Streaming validation**

Token streams cannot wait for completion. Strategy per scenario:

* **Secrets & PII (span detectors):** sliding-window scan over the accumulated buffer with overlap \= max pattern length (512 chars). Matches trigger immediate action: `redact` rewrites the in-flight chunk (buffer holds back `overlap` chars from emission — adds ≤ one chunk of latency); `block` terminates the stream with a structured error frame.  
* **Content safety:** sentence-boundary incremental classification; block terminates stream.  
* **Hallucination:** claim-level checks need complete sentences minimum; run incrementally at sentence boundaries in flag mode, full verdict at stream end. `block_and_explain` in streaming policies is downgraded to end-of-stream retraction (documented behavior; policy linter warns).

### **4.3 Detector services**

Stateless gRPC microservices, one container per detector family, versioned by OCI digest (pinned in bundles). Common contract:

```protobuf
syntax = "proto3";
package guardx.detector.v1;

service Detector {
  rpc Check (CheckRequest) returns (CheckResponse);
  rpc CheckStream (stream StreamChunk) returns (stream CheckResponse);
  rpc Health (HealthRequest) returns (HealthResponse);   // includes model/ruleset versions
}

message CheckRequest {
  string request_id = 1;
  string text = 2;
  Direction direction = 3;                // INPUT | OUTPUT
  bytes config = 4;                       // guard.config (JSON), pre-validated vs schema
  repeated ContextDoc context = 5;        // RAG grounding docs (hallucination)
  map<string,string> metadata = 6;        // app, language hint, etc.
  uint32 deadline_ms = 7;
}

message CheckResponse {
  string detector_version = 1;
  float score = 2;                        // 0..1 risk (1 = certain violation)
  Verdict verdict = 3;                    // PASS | FAIL | ERROR | NEEDS_ESCALATION
  repeated Span spans = 4;                // offsets + entity/rule label + confidence
  string explanation = 5;                 // short machine+human readable reason
  uint32 latency_ms = 6;
}

message Span { uint32 start = 1; uint32 end = 2; string label = 3; float confidence = 4; }
```

#### **4.3.1 PII detector (`presidio-ensemble`)**

* Layer 1: compiled regex recognizers (SSN, phone, email, IBAN, routing, PAN+Luhn, dates) — Rust/Go core called via FFI or reimplemented natively for speed.  
* Layer 2: ONNX-exported NER model (DeBERTa-v3-base token classifier) for names, addresses, org-linked identifiers.  
* Layer 3: context scoring (Presidio-style): proximity words ("SSN:", "member id") raise confidence.  
* **Entity packs**: versioned data files (regexes \+ NER label maps \+ context words) — `financial-us`, `healthcare-us` (MRN/NPI/DEA), `insurance` (policy/claim numbers), `mainframe` (RACF user ID formats). Tenants add custom entities declaratively; no code.  
* Actions implemented in-gateway from spans: `redact` (replace with `[SSN-REDACTED]` tokens, reversible-map optional per policy), `mask` (last-4), `block`.

#### **4.3.2 Secrets detector (`secretscan`)**

* Pure Go, no ML. Vendored Gitleaks-compatible ruleset (TOML) \+ tenant rule packs; Aho-Corasick prefilter on keyword anchors then targeted regex; Shannon entropy scan (base64/hex windows ≥ 20 chars, threshold 4.5/3.0) for unknown formats; optional Luhn/JWT structural validation.  
* `verify_live` (call the provider to confirm a key is active) exists for security-team workflows but is **disabled in prod policies by linter rule** (exfil risk).  
* Target: \< 5 ms p95 at 16 KB payloads, \> 50K RPS per core-cluster. This detector is deterministic: same input \+ ruleset version ⇒ same verdict, always.

#### **4.3.3 Hallucination detector (`nli-groundedness` \+ `llm-judge`)**

Tiered:

* **Tier 1 — NLI groundedness (fast path).** Claim segmentation (sentence splitter \+ conjunction splitting) → each claim scored against supplied `context` docs with an ONNX NLI cross-encoder (DeBERTa-v3 MNLI-class) → aggregate \= min over claims (weakest-claim gating) with per-claim spans.  
* **Tier 2 — LLM judge (borderline only).** Scores in `[escalation_floor, threshold)` escalate to a small self-hosted judge (Llama-3.1-8B-class on vLLM) with a fixed rubric prompt and constrained JSON output: `{claim, supported: bool, evidence_quote_offsets, confidence}`. Judge prompts and rubric are versioned artifacts in the registry (they are policy\!).  
* `requires_context: true` \+ no context supplied ⇒ verdict `NEEDS_ESCALATION` with explanation "ungroundable"; policy decides (block for advice-class apps, flag for chat).  
* Known limitation (documented to customers): probabilistic; benchmark suite scores published per detector version in the catalog. This is honesty-by-design — no detector ships without a benchmark row.

#### **4.3.4 Content safety detector (`safety-ensemble`)**

* Layer 1: small local classifier (Llama-Guard-3-1B or equivalent, ONNX/TensorRT) over the standard taxonomy with per-category thresholds from policy.  
* Layer 2: **custom rules pack** — bespoke tenant rules ("no comparative competitor claims", "no investment advice tone") evaluated by the shared LLM-judge service with rule text injected from the pack. Packs are versioned registry artifacts; rule text changes go through approval like any policy.  
* Multilingual: v1 supports EN \+ policy-declared language allowlist; non-allowlisted language input ⇒ configurable (block/flag). No silent degradation on unsupported languages.

### **4.4 Evidence store**

Append-only pipeline: gateway → Kafka/Redpanda topic `guard.decisions` → (a) ClickHouse for query/analytics, (b) S3 with Object Lock (WORM) as the compliance record, Parquet, daily-partitioned, per-tenant prefix.

#### **Decision event schema (JSON, one per guard evaluation)**

```json
{
  "event_id": "uuid7",
  "ts": "2026-07-16T10:22:31.114Z",
  "tenant": "acme-insurance", "app": "claims-bot", "env": "prod",
  "request_id": "r-...", "conversation_id": "c-... (optional)",
  "policy": "pii-financial-services@3.2.0",
  "bundle_seq": 4812,
  "guard_id": "g-pii-out",
  "scenario": "pii",
  "detector": "presidio-ensemble@1.4.0",
  "direction": "output",
  "verdict": "FAIL", "score": 0.93,
  "spans": [{"start": 211, "end": 222, "label": "SSN", "confidence": 0.97}],
  "action_taken": "redact",
  "latency_ms": 18,
  "evidence_mode": "spans",
  "payload_ref": null,
  "text_hash": "sha256:...",
  "prev_event_hash": "sha256:...",
  "event_hash": "sha256:..."
}
```

* **Tamper evidence:** per-(tenant, app) hash chain — each event embeds the previous event's hash; daily chain-head anchors are signed and stored in the registry. An auditor can verify no event was inserted, altered, or deleted.  
* **Data minimization:** `evidence_mode` from policy controls payload capture: `none` (hashes only), `spans` (offsets \+ labels, no text), `full_text` (encrypted payload in S3, `payload_ref` set, KMS key per tenant, dual-control decrypt). PII policies default to `spans` — the evidence system must not become the leak.  
* **Retention:** per-tenant, per-mode TTLs (ClickHouse TTL \+ S3 lifecycle); WORM lock honors legal-hold flags.  
* **Export:** `evidence:export` job produces a signed archive: events (Parquet), chain-verification report, the exact policy documents in force over the range, detector benchmark sheets. This is the audit deliverable.

---

## **5\. Automation plane**

All three components submit **proposals** via `POST /v1/proposals` with mandatory provenance (`origin`, `origin_ref`). None can write an `approved` policy.

### **5.1 Feed ingestors**

Scheduled workers (Temporal cron), one per feed adapter:

| Feed | Cadence | Produces |
| ----- | ----- | ----- |
| Gitleaks/TruffleHog rulesets (GitHub releases) | daily | Proposal: additive secret patterns → `monotonic_add` class (auto-approvable) |
| Jailbreak/prompt-injection corpora (published datasets, vendor advisories) | daily | New eval cases for the harness \+ proposed custom-rule additions |
| PII recognizer updates (Presidio releases, entity-pack updates) | weekly | Entity pack version bump proposal \+ regression eval run attached |
| Regulatory watch (configured RSS/API sources per framework) | daily | **Notification-only** in v1: opens a review task with the source diff; no auto-drafted policy from regulation text |
| Tenant threat intel (STIX/TAXII, optional) | configurable | Custom pattern proposals |

Every feed proposal attaches an **eval report**: the harness (§7) replays the tenant's golden set \+ red-team suite against current vs. proposed policy and includes the delta. Reviewers approve a measured change, not a diff of regexes.

### **5.2 LLM policy synthesizer**

Pipeline (Temporal workflow):

1. **Ingest** customer documents (compliance manual, data classification policy, brand guidelines) — PDF/DOCX → text with page/paragraph anchors.  
2. **Extract** candidate rules: LLM pass with a constrained JSON schema output — `{rule_text, source_anchor, scenario, proposed_guard}` — using a versioned extraction prompt (registry artifact). Null-over-guess discipline: the model must emit `scenario: null` rather than force-fit an unmappable statement; nulls route to a human triage queue.  
3. **Compile** each candidate into a concrete guard block (entity selections, thresholds from the matching industry profile default, on\_fail from a severity heuristic table — the heuristic table itself is a reviewable artifact).  
4. **Validate**: JSON Schema \+ detector config schema \+ policy linter (e.g., "verify\_live in prod", "block\_and\_explain under streaming").  
5. **Evaluate**: run the harness with synthetic positives generated per rule ("generate 30 outputs that violate this rule") \+ tenant golden negatives; attach precision/recall estimate.  
6. **Submit** as a draft policy with per-guard provenance: every guard cites the source paragraph it came from.

Reviewer UX: side-by-side — source paragraph ↔ generated guard ↔ eval numbers — approve/edit/reject per guard. Target: a 40-page policy manual becomes a reviewed, enforcing policy in \< 4 hours of human time.

### **5.3 Auto-tuner**

Inputs: decision events \+ feedback events (`POST /v1/feedback` — thumbs from app UX, analyst dispositions from the review console, appeal outcomes) \+ sampled human review labels.

* Nightly job per (tenant, guard): fit threshold-vs-FP/FN curves from labeled data; when a threshold move improves the tenant's stated objective (e.g., "FP rate \< 2% subject to FN rate \< 0.1%") with statistical confidence (min sample sizes enforced), submit a proposal with the evidence: "0.85 → 0.88 cuts FPs 31%, zero missed detections across 1,412 labeled samples (95% CI attached)."  
* **Shadow mode:** any proposed version can be deployed `shadow` in a bundle — gateway evaluates it non-blocking in parallel and logs `shadow_verdict` alongside live verdicts. Promotion UI shows the live-vs-shadow delta over real traffic before approval. (Same parallel-run assurance pattern as a payroll cutover: prove the new system agrees before it takes over.)  
* Drift alarms: verdict-rate change-point detection per guard (block-rate spike/collapse) opens an incident task — catches upstream model changes and attack campaigns.

---

## **6\. Cross-cutting: security, tenancy, deployment**

* **Tenancy:** single-tenant-per-namespace (recommended for regulated) or shared-plane multi-tenant with Postgres RLS \+ per-tenant Kafka ACLs \+ per-tenant KMS keys. Tenant ID is threaded through every API, event, and storage prefix.  
* **Secrets handling inside GuardX:** the platform sees raw prompts/completions; gateway memory is the trust boundary. No payload persistence outside evidence-mode rules; disable core dumps; mTLS everywhere (SPIFFE/SPIRE or mesh-issued certs); FIPS-mode crypto build flag for federal.  
* **Supply chain:** detectors and rule/entity packs are OCI artifacts, signed (cosign), pinned by digest in bundles; SBOM per release; the gateway refuses unpinned detector versions. (This is the answer to the Hub-installs-arbitrary-code problem.)  
* **Air-gap:** all models self-hosted; feeds replaceable by offline bundle drops; no call-home.  
* **Deployment:** Helm chart; profiles for (a) single-node docker-compose dev, (b) HA production (3× gateway, 2× per detector, Postgres HA, 3-broker Redpanda, ClickHouse pair). GPU pool optional — all ML detectors run CPU-ONNX at reduced throughput for small deployments.

---

## **7\. Testing & evaluation harness (first-class subsystem)**

* **Golden sets:** per-tenant labeled corpora (violations \+ clean traffic samples, from evidence store with analyst labels). Every policy promotion runs the golden set; regression beyond tolerance blocks the promotion (override requires approver \+ note).  
* **Red-team suite:** bundled adversarial cases per scenario (obfuscated SSNs `4-5-2 dash tricks`, base64/leet secrets, multilingual toxicity, prompt-injection payloads) refreshed by the feed ingestors; runs in CI against every detector release.  
* **Detector benchmarks:** each detector version publishes precision/recall/latency on public \+ internal suites into the catalog; the policy UI shows the numbers next to every detector picker. No un-benchmarked detector is selectable.  
* **Policy linter:** static checks at draft time (contradictory guards, streaming-incompatible actions, missing fail\_mode, evidence\_mode=full\_text under a PII policy, verify\_live in prod).  
* **Load/latency CI:** k6 suites asserting the §4.1 budgets on every gateway release; p95 regression fails the build.

---

## **8\. Observability & operations**

* OpenTelemetry traces end-to-end (client → gateway → detectors), metrics via Prometheus: per-guard verdict rates, latency histograms (p50/p95/p99), detector error rates, circuit-breaker state, bundle age, shadow-delta.  
* Grafana dashboards shipped in the Helm chart: Latency, Verdicts, Policy drift, Evidence pipeline lag.  
* Alert defaults: fail-open occurrences (security incident class), fail-closed spikes (availability class — separate runbooks), bundle staleness, chain-anchor verification failure.  
* Admin console (web): policy authoring/review/diff, approval queue, evidence search, shadow comparisons, analyst review queue for flagged events.

---

## **9\. Public API surface summary**

**Data plane** (gateway):

* `POST /v1/proxy/{app}/chat/completions` — OpenAI-compatible proxy (also `/messages` Anthropic-compatible)  
* `POST /v1/guard/check` — validate-only: `{app, direction, text|messages, context?} → {verdict, actions, guards:[...]}`  
* `POST /v1/feedback` — feedback events for the auto-tuner

**Control plane:** §3.5 table.

**SDKs:** Python \+ TypeScript, thin clients; one-liner integration:

```py
from guardx import GuardedClient
client = GuardedClient(app="claims-bot", base_url="https://guardx.internal")  # wraps openai/anthropic SDK
```

---

## **10\. Recommended tech stack**

Optimized for the two stated constraints: minimal latency and easy maintenance. Bias: **boring, few languages, few moving parts.**

| Layer | Choice | Rationale |
| ----- | ----- | ----- |
| Guard Gateway | **Go** (stdlib net/http \+ gRPC; optional Envoy ext\_proc build) | Predictable low latency without GC tuning drama, single static binary, trivial ops. Rust would shave microseconds at real maintenance cost; Python cannot hit the budgets. |
| Secrets detector | **Go** (same repo as gateway; can compile in-process) | Deterministic regex/entropy — no ML runtime needed; in-process option removes a network hop for the hottest path |
| PII / NLI / safety detectors | **Python 3.12 \+ FastAPI-gRPC (grpclib) \+ ONNX Runtime** (CPU) / **Triton Inference Server** (GPU option) | Python keeps the ML ecosystem (Presidio, HF tokenizers) maintainable; ONNX export removes PyTorch from the serving path — small images, fast cold-start, CPU-viable |
| LLM judge | **vLLM** serving Llama-3.1-8B-class, OpenAI-compatible endpoint | Self-hosted, air-gap capable, continuous batching for judge bursts |
| Control API | **Python 3.12 \+ FastAPI \+ SQLAlchemy/Alembic** | Not latency-critical; fastest to build/maintain; shares models with automation plane |
| Registry DB | **PostgreSQL 16** (JSONB \+ RLS) | Boring, transactional, RLS for tenancy; JSONB fits document-style policies with relational audit |
| Bundle cache / pub-sub | **Redis 7** | Bundle push \+ gateway coordination; loss-tolerant (S3 mirror is the fallback) |
| Event pipeline | **Redpanda** (Kafka API) | Kafka semantics without ZooKeeper/JVM ops burden; single binary |
| Evidence analytics | **ClickHouse** | Column-store for billions of decision events; TTLs native |
| Evidence archive | **S3 / MinIO with Object Lock** | WORM compliance record; MinIO for self-host/air-gap |
| Workflow engine | **Temporal** (Python SDK) | Durable multi-step automation (synthesizer, feeds, tuner) with retries/visibility for free |
| Signing/keys | **Ed25519 via KMS/Vault Transit; cosign for OCI artifacts** | Standard, auditable, HSM-compatible |
| Packaging/deploy | **Kubernetes \+ Helm; docker-compose dev profile** | Industry default; single-node path for POCs |
| Observability | **OpenTelemetry \+ Prometheus \+ Grafana** | De facto standard; ships in chart |
| Admin console | **React \+ TypeScript (Vite)** on the Control API | Standard, hireable |
| API contracts | **OpenAPI 3.1 (REST) \+ protobuf (detectors)**, generated clients | Contract-first keeps SDKs thin and honest |

**Two languages total** (Go for the hot path, Python for ML \+ control \+ automation) plus TypeScript for the console — the maintenance ceiling stays low.

**Latency design notes:** guards fan out in parallel (phase latency \= max, not sum); secrets in-process; ONNX models quantized (INT8) with sub-25ms CPU inference for the NER/NLI models at 512-token windows and sliding-window chunking for long payloads; connection pooling \+ gRPC keepalive gateway↔detectors; policy index fully in-memory (bundle swap is an atomic pointer flip); evidence emission is async fire-and-forget with local disk spool if the broker is down (evidence loss alarms, never blocks the response path).

---

## **11\. Milestones & build order**

| Milestone | Scope | Exit criteria |
| ----- | ----- | ----- |
| **M0 — Skeleton** (wks 1–3) | Registry schema \+ Control API CRUD \+ policy JSON Schema \+ linter; gateway proxy mode with in-memory policy, no detectors | Policy created→approved→bundle→gateway hot-swap demo |
| **M1 — Deterministic tier** (wks 3–7) | Secrets detector (in-process) \+ PII detector (regex \+ ONNX NER) \+ redact/block actions \+ streaming sliding window | \< 30 ms p95 combined on 4K payloads; golden-set precision ≥ 0.95 on financial entity pack |
| **M2 — Evidence** (wks 6–10) | Redpanda→ClickHouse/S3 pipeline, hash chain, evidence modes, export job | Chain verification tool passes on 10M synthetic events; export produces auditor archive |
| **M3 — ML tier** (wks 9–14) | Content safety ensemble \+ NLI groundedness \+ LLM judge (vLLM) \+ tiered escalation \+ shadow mode | \< 130 ms p95 full tier-1 stack; published benchmark rows for all detectors |
| **M4 — Profiles \+ console** (wks 12–17) | Industry packs (baseline, glba-nydfs, hipaa) \+ admin console (author/review/diff/approve, review queue) | Tenant onboards via profile in \< 1 day without vendor help |
| **M5 — Automation** (wks 16–22) | Feed ingestors (secrets, red-team) \+ auto-tuner \+ shadow-delta promotion UI; then LLM synthesizer | Feed→proposal→auto-approve monotonic path live; synthesizer converts a 40-pg manual to reviewed policy \< 4 hrs human time |
| **GA hardening** (wks 22–26) | HA chart, FIPS build, pen test, docs, k6 latency CI gates | SOC 2-ready control narrative; all §4.1 budgets green in CI |

Team shape: 2 Go, 2 Python/ML, 1 frontend, 1 DevOps/SRE, \+ fractional PM/compliance SME.

---

## **12\. Risks & open questions**

| \# | Risk / question | Mitigation / decision needed |
| ----- | ----- | ----- |
| R1 | Hallucination detection is inherently probabilistic; customers may over-trust it | Mandatory benchmark disclosure in catalog \+ "flag not block" default outside advice-class profiles |
| R2 | LLM judge adds a self-hosted model dependency (GPU cost) | CPU-quantized fallback documented with throughput table; judge optional per policy |
| R3 | Evidence store as a PII honeypot | `spans` default, per-tenant KMS, dual-control decrypt, minimization linter rule |
| R4 | Synthesizer produces plausible-but-wrong guards | Human approval mandatory; per-guard source citation; eval report attached; null-over-guess extraction |
| R5 | Streaming redaction UX (held-back chars) | ≤ one chunk delay measured; product decision: expose `stream_hold` as visible typing indicator? **Open** |
| R6 | Multi-turn attacks out of scope in v1 | Documented limitation; conversation\_id captured now so v2 conversation guards have data |
| Q1 | Reversible redaction (tokenization vault) in v1 or v2? | **Open** — pulls in a vault component; recommend v2 |
| Q2 | Anthropic/OpenAI proxy parity scope (tools, images pass-through untouched?) | **Decision needed** M0: v1 passes non-text modalities through unvalidated with a policy-linter warning |
| Q3 | Per-request policy override (header) for internal testing | Recommend: allowed only in non-prod environments, always evidenced |

---

## **13\. Compliance mapping (summary)**

| Framework | GuardX control |
| ----- | ----- |
| NYDFS 500.03/500.06 | Approved written policies (registry), audit trail (evidence chain) |
| SOX ITGC | Change management (approval workflow, SoD), access control (RBAC), immutable audit |
| HIPAA §164.312 | PHI redaction, evidence minimization, encryption, access logging |
| SR 11-7 | Detector benchmark disclosure, versioned model inventory, shadow validation |
| EU AI Act (high-risk) | Logging (Art. 12), human oversight (review queue, Art. 14), accuracy/robustness records (Art. 15\) |
| PCI DSS 3.4 | PAN detection/masking, truncated evidence |

## **14\. v2 roadmap (non-binding)**

Conversation-level guards (cumulative-risk scoring over `conversation_id`); agentic tool-call authorization (pre-invocation policy checks); multimodal detectors; reversible tokenization vault; behavioral anomaly guards (per-user baselines — VigilX-pattern applied to LLM traffic); policy-as-code Terraform provider.

---

*End of specification.*

