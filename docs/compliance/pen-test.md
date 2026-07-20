# External pen test — outstanding deferral

**Status:** Not started. Track this before pursuing SOC 2 Type 2 attestation, enterprise sales (Fortune 500 typically require a pen test dated within the last 12 months), or cyber-insurance premium reductions.

## Why buyers ask for it

| Buyer | What they want to see |
| ----- | ----- |
| SOC 2 auditor | Report attesting that a qualified firm attempted to break in and documenting what they found + how it was remediated |
| Enterprise procurement | Same report + attestation letter, usually via a SIG questionnaire response |
| Cyber-insurance carrier | Same, often with a specific findings-severity threshold for policy issuance |

The report is the deliverable, not the security improvement. That said, a good engagement finds real bugs and the remediation improves the product — worth doing right, not as theater.

## Scope a firm would engage on

GuardX has four testable surfaces:

1. **Control API** (`:8080`) — REST, authenticated, multi-tenant, drives policy state changes
2. **Gateway** (`:8081`) — reverse proxy in front of an upstream LLM; hot-swap policy loader
3. **Detectors** (`:9100/9200/9300`) — HTTP receivers; internal-only in normal deployments but internet-reachable if misconfigured
4. **Console** — SPA, holds bearer tokens, drives all Control API state changes

Out of scope typically: the underlying Postgres (customer's responsibility), the upstream LLM provider (their contract), the browser TLS stack.

Ask the firm to focus on:

- **Auth bypass** on `/v1/proposals` (invariant I3 — automation must not be able to write `approved` policies). This is the highest-value security invariant.
- **Tenant isolation** — can tenant A read tenant B's evidence via header manipulation or timing attacks?
- **Signed-bundle handling** — can a compromised Control API push a policy the gateway would install without the operator noticing? The chain-anchor rotation window is the interesting variable here.
- **JWT verification** — key confusion, algorithm downgrade, JWKS spoofing via DNS.
- **SSRF from detectors** — the safety detector calls out to a configured LLM provider; can an attacker steer it to internal endpoints via a crafted rubric?
- **Injection into the LLM judge prompt** — synthesizer input path takes arbitrary text. Prompt injection here doesn't yield code execution, but a crafted policy manual could bias the extraction.

## Pre-engagement hardening

The following are the wins a competent pen test would flag on the first pass. Doing them before the engagement means the report focuses on interesting findings rather than obvious hygiene.

- [ ] **Auth-endpoint rate limiting.** No limit on `POST /v1/proposals` today. Add per-principal rate limits (e.g., 60/min for authors, 600/min for service tokens). Redis or in-memory token bucket.
- [ ] **Security headers on Control API responses.** `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. A middleware — one file.
- [ ] **CSP on console.** `Content-Security-Policy: default-src 'self'; connect-src 'self' https://<idp> https://<control>`. Add via Vite plugin or the serving nginx config.
- [ ] **Secrets scanning in CI.** Wire Gitleaks (which we already ship in the detector) as a CI job on the repo itself — dogfooding + baseline hygiene.
- [ ] **Dependency audit in CI.** `pip-audit`, `npm audit --production`, `govulncheck` — fail the build on `high`/`critical`.
- [ ] **Session invalidation on role change.** When an IdP admin demotes a user from `approver` to `viewer`, the JWT they already hold is still valid until expiry. If sub-hour granularity matters, shorten JWT TTL + tell the runbook.
- [ ] **Audit log for auth failures.** Currently only `policy_audit` records state changes; auth-failure events (bad JWT, missing role) log to stderr but aren't queryable. A dedicated `auth_events` table with rate-limited insert.
- [ ] **Tenant-ID header stripping.** Ensure that when the gateway forwards a request to an upstream LLM, request headers we set (`X-Tenant`, etc.) can't be spoofed by the caller. Whitelist headers rather than passthrough.
- [ ] **SSRF allowlist on judge providers.** `config/providers.yaml` is trusted config, but a compromised operator could point it at internal endpoints. Add an env-var allowlist of hostnames the OpenAI-compat backend will connect to; refuse anything else at startup.
- [ ] **Signing-key rotation runbook.** We ship [oidc-setup.md](../runbooks/oidc-setup.md) for JWKS rotation. Add the equivalent for the Ed25519 bundle-signing key.

Each of these is a small, self-contained code + docs change. Doing all of them is maybe a week of work.

## Engagement path

1. **Pick a firm.** For B2B SaaS at this scale, options in rough order of thoroughness/cost:
   - Bishop Fox / NCC Group / Trail of Bits — top tier, ~$50–100K for a two-week engagement
   - Cobalt / HackerOne (with a scoped bounty) — hybrid model, ~$15–40K
   - Independent consultants — variable

2. **Scope the engagement.** Give them:
   - The compliance mapping ([mapping.md](mapping.md))
   - This scope doc
   - Access to a staging instance with a known dataset
   - Two admin credentials (one for the "insider-threat" leg)
   - A copy of the runbooks so they don't waste hours on config discovery

3. **Fixed-price vs T&M.** For a first engagement, fixed-price is safer. T&M works when there's a trust relationship.

4. **Report format.** Ask for both the executive summary (auditor / customer artifact) and the technical findings (engineering artifact). Attestation letter as a separate deliverable.

5. **Remediation window.** Standard is 30 days for critical/high. Build a validation retest into the scope — most firms include one.

## When to actually do this

Do the pen test:

- Once the pre-engagement hardening list is done (findings would be embarrassing otherwise)
- Before the first SOC 2 Type 2 audit window
- Before the first Fortune 500 procurement discussion

Do **not** do this if:

- The product is still pre-revenue and no customer has asked
- You're going to substantially refactor before shipping — the test would age out before the audit

## References

- SANS: Security in Web Application penetration testing — https://www.sans.org/white-papers/33089/
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- SOC 2 pen-test requirements: SOC 2 Type 2 trust criterion `CC7.5` requires periodic vulnerability + pen test
