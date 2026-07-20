# Contributing to GuardX

Thanks for considering a contribution. This document covers what we're
looking for, how the codebase is organised, and the mechanics of getting a
change merged.

## What we're looking for

- **Bug reports** with reproduction steps.
- **Fixes** for anything the tests catch or that a runbook flags.
- **New detectors** — regex/entropy rules, ONNX classifiers, or LLM-judge
  rubrics. Follow the interfaces at [proto/detector.proto](proto/detector.proto)
  and the shape in the existing detector packages.
- **New profile packs** for compliance frameworks not yet covered.
- **New LLM providers** — extend [config/providers.yaml](config/providers.yaml)
  or add a new backend class in `detectors/llm_judge/llm_judge/backends.py`.
- **Documentation** — runbooks, deployment recipes, compliance mapping
  additions.

Before opening a large PR, please open a discussion issue first — we may
have context on why a thing works the way it does, or a change already
in flight.

## What we're not looking for

- Fundamental architecture changes without a discussion first.
- Framework re-writes.
- New dependencies without a strong justification. The gateway is
  stdlib-only Go for a reason; every Python venv is deliberately small.
- Vendored copies of upstream data (secret rules, entity packs) without
  license attribution.
- Cosmetic-only changes (spacing, comment reformatting) that don't
  improve the code.

## Codebase orientation

See [README.md](README.md) for the top-level layout. Load-bearing tests
per component:

| Component | Test command |
| ----- | ----- |
| Go gateway | `cd gateway && go test ./...` |
| Python control API | `cd control && pytest` |
| PII detector | `cd detectors/pii && pytest` |
| LLM judge | `cd detectors/llm_judge && pytest` |
| Safety detector | `cd detectors/safety && pytest` |
| NLI detector | `cd detectors/nli && pytest` |
| Automation | `cd automation && pytest` |
| Console | `cd console && npm run typecheck` |
| Chart | `helm lint deploy/helm` |

Everything above should pass before a PR merges.

## Development environment

```sh
# Backend stack (Postgres + control + upstream + PII + gateway).
docker compose -f deploy/compose/docker-compose.yml up --build -d

# Console dev server.
cd console && npm install && npm run dev
```

Python components use per-package venvs (see the `pyproject.toml` in each).
Go stays at `go.mod`-vendored dependencies — no separate GOPATH ceremony.

## Coding conventions

- **Go**: `gofmt`-clean, `golint` friendly. No third-party runtime deps in
  the gateway (test deps are OK).
- **Python**: `ruff` config is in `control/pyproject.toml`. Follow it in
  all packages.
- **TypeScript**: `tsc --noEmit` must pass. No `any` in new code unless
  the boundary genuinely lacks a type.

Consistent-style pointers you'll pick up by reading:

- Errors are values in Go — return early, wrap with `%w`.
- FastAPI dependencies are the auth mechanism — new routes use
  `Depends(require_role(...))` or `Depends(current_principal)`.
- Every state-changing route stamps `policy_audit` or the equivalent
  before commit.
- Every event carries `policy_id@version` and `detector_id@version` —
  spec invariant I4. Don't drop them.

## Commit + PR mechanics

1. Fork, branch, commit. One logical change per commit.
2. Include tests for anything non-trivial.
3. Push and open a PR against `main`. Reference any related issue.
4. Fill in the PR template — what changed, why, how tested.
5. CI runs the full test suite + helm lint + latency gate. Green is
   required before review.
6. A maintainer reviews. Expect a round or two of feedback.
7. Merge is squash-and-merge by default. Commit-per-review-round is fine
   while iterating; the final message goes on the merge commit.

## Sign-off

By contributing, you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE) and you have the right to make the
contribution. If a commit represents a Contribution (as defined by the
license), Section 5 applies.

We do **not** require a separate CLA. The Apache-2.0 `NOTICE` handles
attribution.

## Security-sensitive contributions

Please do not open a public PR for a vulnerability fix. Follow the private
reporting flow in [SECURITY.md](SECURITY.md); the maintainer will coordinate
the fix and disclosure.

## License of contributed data

If your PR includes vendored data (detector rules, entity packs, rubric
prompts, benchmark corpora), include the upstream license in [NOTICE](NOTICE)
and — if the license requires — leave the copyright headers intact.

## Getting help

- Open an issue with the `question` label for design questions.
- For runtime problems, the [runbooks](docs/runbooks/) usually have the
  fastest answer.
- For everything else, see [README.md](README.md).
