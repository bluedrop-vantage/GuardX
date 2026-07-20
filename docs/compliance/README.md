# Compliance documentation

Documents for compliance / procurement / audit engagements. If a customer asks "does GuardX support X?", the answer lives here.

| Document | Purpose | Status |
| ----- | ----- | ----- |
| [mapping.md](mapping.md) | Framework-to-control mapping with artifact citations (NYDFS 500, SOX ITGC, HIPAA §164.312, SR 11-7, EU AI Act, PCI DSS) | Complete |
| [fips.md](fips.md) | FIPS 140 scope, procurement path, and the "FIPS-mode running" vs "FIPS 140 validated" distinction | Not started — deferred until a buyer needs it |
| [pen-test.md](pen-test.md) | External pen-test scope, pre-engagement hardening checklist, engagement path | Not started — deferred until SOC 2 Type 2 or first enterprise procurement |

## The honest picture

GuardX ships with the **audit-facing controls** — evidence chain + signed anchors, approval workflow with SoD, RBAC with real OIDC, framework mappings — that satisfy the *technical* half of most compliance frameworks.

The **procurement-facing artifacts** — a NIST CMVP certificate, a pen-test attestation letter, a SOC 2 Type 2 report — are deliverables produced by external parties (labs, security firms, auditors). GuardX can't produce them on its own; the docs above are what the platform and its operators need to have ready when the engagement begins.

Both fips.md and pen-test.md include:

- **When to actually do it** — so the platform isn't dragged into work its buyer profile doesn't yet require
- **Concrete pre-engagement work** — the code and process changes that make the eventual external engagement productive rather than embarrassing
- **Budget + timeline ranges** — realistic ballparks for the actual engagement

Both documents are intended to be handed to a compliance officer, sales engineer, or a security firm during pre-sales. They're plain text, not marketing.
