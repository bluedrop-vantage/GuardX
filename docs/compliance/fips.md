# FIPS 140 — outstanding deferral

**Status:** Not started. Track this before pursuing US federal, defense contractor (CMMC), or state-regulated banking/healthcare buyers.

## What FIPS 140 is

A NIST-run validation program that certifies specific *cryptographic modules* (not products). US regulations that reference FIPS 140:

- **FISMA** (US federal agencies) — hard requirement for any crypto in the boundary
- **CMMC 2.0** (defense contractors) — required at Level 2+
- **NYDFS Part 500** (large NY-regulated FIs) — encryption-in-use requirements often satisfied via FIPS-validated modules
- **HIPAA** — not required, but a FIPS module is one accepted mitigation for §164.312(e) transmission-security controls

Two levels of claim:

| Claim | What it means | What GuardX would need |
| ----- | ----- | ----- |
| **FIPS-mode running** | The crypto module is *configured* to only use FIPS-approved algorithms in FIPS-approved ways | Buildable in a session — see below |
| **FIPS 140 validated** | A NIST-authorized lab has tested the module and NIST issued a certificate under the CMVP | External procurement engagement, ~$50–150K, ~6–12 months |

Most buyers say "FIPS 140" and accept a running FIPS-mode build **backed by a validated module underneath** (e.g., the FIPS-validated version of OpenSSL, or the BoringSSL FIPS module Google runs). GuardX doesn't need to run its own CMVP submission — it needs to *use* validated modules and prove it does.

## Where crypto lives in GuardX

| Component | Uses | FIPS-mode path |
| ----- | ----- | ----- |
| Gateway (Go) | Ed25519 verify, SHA-256, HMAC internally, TLS in `net/http` | Go's `boringcrypto` (Go 1.19–1.23) or `GOFIPS=1` (Go 1.24+ / FIPS 140-3 mode). Both compile to a build that only uses BoringCrypto's FIPS-validated primitives. |
| Control API (Python) | Ed25519 sign (via `cryptography`), SHA-256, JWT verify | `cryptography` calls into system OpenSSL. Runs FIPS-mode when the OS is FIPS-mode (RHEL, UBI FIPS, Amazon Linux 2 FIPS, Ubuntu FIPS). No Python code change. |
| Detectors (Python) | Nothing crypto — just HTTP + regex + ML | Not affected. |
| Automation (Python) | Same as Control API | Same path. |
| Console (browser) | Whatever the browser provides for TLS | Out of scope — user's browser choice. |

The point: GuardX has a *small crypto surface* and it's already in libraries with existing FIPS validation stories. No custom crypto to justify.

## What a FIPS-mode variant would ship

1. **Gateway Dockerfile variant** — build with `GOEXPERIMENT=boringcrypto` (Go 1.23) or `GOFIPS=1` (Go 1.24+). A build tag exposes a `FIPSMode()` function that returns `true` and refuses to start if the underlying build isn't FIPS-mode. This is the "prove it's on" hook.
2. **Control API Dockerfile variant** — base off `registry.access.redhat.com/ubi9/ubi:latest` with the OpenSSL FIPS module enabled, install Python from the UBI repos (not `python:slim`), point `PIP_INSTALL` at the same. Reject boot if `cryptography.hazmat.backends.openssl.backend._lib.FIPS_mode() != 1`.
3. **Helm values variant** — `fips.enabled: true` selects the FIPS image tags across all deployments.
4. **CI job** — a smoke test that boots the FIPS variant and checks the boot-time assertion.
5. **Compliance narrative** — a paragraph in [mapping.md](mapping.md) that states which validated modules are relied on, with links to the CMVP certificate for each.

Nothing above is a full solution — a real customer engagement will also want to see:

- A **CMVP certificate reference** for each cryptographic module in the boundary (Go BoringCrypto certificate: currently CMVP #4407; OpenSSL FIPS Provider 3.0 module: CMVP #4282, etc. — verify the current active cert before quoting)
- **Boundary diagram** naming which processes/files are inside the FIPS boundary
- **Non-approved algorithm list** — anything GuardX does with crypto that's *not* FIPS-approved (currently: nothing user-facing; internal caching hashes if any)
- **Zeroization behaviour** for keys — for GuardX this is trivial because we don't hold long-lived keys in gateway memory

## When to actually do this

Do the FIPS-mode variant **now** if:

- A specific customer has said "we need FIPS-mode running for procurement"
- You are targeting FedRAMP Moderate or higher (FIPS-mode is a prerequisite)

Do **not** do this if:

- Your buyer profile is SaaS-first commercial. Nobody there asks; you'd be paying the operational tax on RHEL UBI FIPS images for no revenue.

## Procurement path

1. Confirm what the buyer actually needs — "FIPS 140-2 Level 1 running" vs "FIPS 140-3 validated" vs "FIPS-approved algorithms only" are three different asks with wildly different work.
2. If they need the actual CMVP certificate on GuardX itself (rare): engage a NIST-authorized CST lab (e.g., Atsec, Acumen, LGS). Budget stated above.
3. If they need running FIPS-mode backed by already-validated modules (common): ship the variant described above.
4. Attach the CMVP certificates for the modules GuardX depends on to the customer's questionnaire.

## References

- CMVP program: https://csrc.nist.gov/projects/cryptographic-module-validation-program
- Go FIPS-mode overview: https://go.dev/doc/security/fips140
- Red Hat UBI FIPS: https://catalog.redhat.com/software/base-images (filter for FIPS)
- OpenSSL FIPS provider: https://openssl-library.org/source/fips.html
