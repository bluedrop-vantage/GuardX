# Security policy

GuardX is a security-critical platform — the whole point is to be the thing
that guards other systems. We take vulnerability reports seriously.

## Supported versions

The current major version is supported. Older versions receive fixes only
for critical severity issues.

| Version | Supported |
| ----- | ----- |
| 0.x (current) | ✅ Yes |
| Anything older | ❌ No |

## Reporting a vulnerability

**Do not open a public GitHub issue** for a suspected security vulnerability.
Public disclosure before a fix is available puts every operator running
GuardX at risk.

Instead, one of these channels:

1. **Private security advisory** on GitHub — go to the repo's Security tab
   → "Report a vulnerability". This is the preferred path; it gives us a
   private thread and a CVE mint on disclosure.
2. **Email** — `ajgit7862@gmail.com` (or the maintainer's address in the
   repo's [`CODEOWNERS`](CODEOWNERS) if that file exists). Encrypt with our
   PGP key if you have sensitive PoC material; ask for the key on the same
   thread.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal PoC.
- The GuardX version(s) affected.
- Your name/handle for the credit line (optional — you can stay anonymous).

## What happens next

| When | What |
| ----- | ----- |
| Within **48 hours** | We acknowledge receipt. |
| Within **7 days** | We reproduce or ask clarifying questions. |
| Within **30 days** | We ship a fix, or share our best-effort estimate if the fix requires longer work. |
| On release | We publish a security advisory with a CVE, credit you (if you want), and notify operators. |

Critical severity fixes are back-ported to the current major version. Others
land in the next scheduled release.

## Coordinated disclosure

We follow a **90-day disclosure window** by default:

1. You report; we acknowledge.
2. We work on a fix. You test the fix if you're willing.
3. We release the fix and publish the advisory.
4. **90 days after the initial report**, you're free to publish your own
   write-up regardless of whether a fix has shipped.

If the issue is being actively exploited in the wild, we shrink the window
by agreement.

## Scope

**In scope** — reports we act on:

- Authentication or authorization bypass in the Control API or gateway.
- Ability to install an unsigned or tampered bundle at the gateway.
- Ability to modify or delete evidence rows without breaking the hash chain.
- Any way for an untrusted request to escalate to admin actions.
- Any way for a tenant to read another tenant's data.
- SSRF, injection, or remote-code-execution flaws anywhere in the platform.
- Cryptographic issues (wrong algorithm, wrong parameters, key reuse).
- Vulnerable dependency versions we ship — please include the CVE and the
  version we're on.

**Out of scope** — we typically decline these:

- Issues in third-party services (Together.ai, DeepInfra, Supabase, etc.).
  Report those to the service directly.
- Denial-of-service via unrestricted resource use (operators are expected to
  set their own rate limits). We do accept DoS reports if a single request
  can wedge the platform.
- Bugs in unsupported versions.
- Missing security headers unless they lead to concrete impact.
- Best-practice suggestions without a demonstrated impact.
- Findings that require compromised infrastructure (e.g., "if you have DB
  admin, you can modify data").

## Hall of fame

Contributors who have responsibly disclosed vulnerabilities will be listed
here (with permission) once we have any to list.

## Related documents

- [docs/compliance/pen-test.md](docs/compliance/pen-test.md) — pre-engagement
  hardening checklist and pen-test scope.
- [docs/runbooks/](docs/runbooks/) — operational runbooks including
  security-incident-class alerts (`fail-open.md`, `chain-anchor-fail.md`).
