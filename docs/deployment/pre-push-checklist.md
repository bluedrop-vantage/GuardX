# Pre-push checklist

Everything to verify before pushing GuardX to a public GitHub repository for
the first time. Skipping any of these can leak credentials, embarrass the
project, or trigger downstream security incidents.

Work top-to-bottom; each item is a one-liner or two.

## 1. Rotate every credential that has ever been in `.env`

**Every key in the current `.env` should be treated as burned:**

- Supabase `SUPABASE_SECRET_KEY` — rotate in the Supabase dashboard (Project
  Settings → API → JWT Secret / service_role key).
- Supabase database password (the `Smit@4088764431` in `POSTGRES_URI`) —
  Project Settings → Database → Reset database password.
- `TOGETHER_AI_API_KEY` — Together.ai dashboard → API keys → rotate.
- `DEEPINFRA_API_KEY` — DeepInfra dashboard → API keys → rotate.
- Any dev signing keys under `control/dev-signing-key.*` — regenerate for
  each fresh clone.

Why: this file has been open in an editor, referenced in chat logs, and
shell-history'd. Any of those channels is a leak.

## 2. Confirm `.env` is not tracked

```sh
# Anywhere in the repo:
git status --ignored | grep -E "\.env$"    # should show "Ignored files:"
git check-ignore -v .env                    # should print the rule that ignored it
```

If either fails, add `/.env` at the top of `.gitignore` and `git rm --cached
.env` **before** the first push.

## 3. Confirm no other secrets crept in

```sh
# Look for anything that pattern-matches an obvious secret in tracked files.
git ls-files | xargs grep -HInE '(sk_(live|test)_|xox[baprs]-|ghp_|AKIA[0-9A-Z]{16}|tgp_v1_|sb_secret_|-----BEGIN [A-Z ]*PRIVATE KEY-----)' 2>/dev/null
```

Expected output: **empty**. If anything shows up, remove the file, rotate the
key, then continue.

For continuous protection, install [gitleaks](https://github.com/gitleaks/gitleaks)
locally and run `gitleaks detect --source . --no-git` before every push. GuardX
already vendors a Gitleaks-compatible ruleset in the secrets detector — worth
dogfooding.

## 4. Sanity-check `.gitignore`

```sh
# Do a dry-run `git add .` in a tmpfs clone. Nothing should appear that
# looks like a secret, a venv, a build artifact, or an OS junk file.
tmp=$(mktemp -d)
rsync -a --exclude=.git . "$tmp"/
cd "$tmp"
git init -q --initial-branch=main
git add . --dry-run 2>&1 | head -40
```

Expected: source files, config, docs. No `.venv/`, `node_modules/`,
`__pycache__/`, `.env`, `dev-signing-key.*`, `sbom/`, or `.DS_Store`.

## 5. Verify LICENSE + NOTICE + SECURITY + CONTRIBUTING + CoC exist

```sh
ls -la LICENSE NOTICE SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md
```

All five should be present at the repo root. If any is missing, GitHub will
flag the repo as "incomplete" in its community standards check.

## 6. Verify contact addresses

Two files carry inboxes reporters will contact:

- Vulnerability reports — [SECURITY.md](../../SECURITY.md) `## Reporting a vulnerability`
- CoC violation reports — [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) `## Enforcement`

If you're forking, replace both with an address you actually monitor.
Placeholder inboxes mean a security reporter has nowhere to go.

Quick sanity check the address you're publishing under is one you control:

```sh
grep -RhoE '[[:alnum:]_.+-]+@[[:alnum:].-]+' SECURITY.md CODE_OF_CONDUCT.md | sort -u
```

## 7. Update the copyright line

The Apache-2.0 [LICENSE](../../LICENSE) footer and [NOTICE](../../NOTICE)
both say `Copyright 2026 GuardX contributors`. If you're publishing under a
company name, replace with:

```
Copyright 2026 <Your Legal Entity> and GuardX contributors
```

## 8. Attribute the spec

The GuardX spec at repo root
(`GuardX — Centralized LLM Guardrail Platform.md`) — confirm authorship and
that publishing it under Apache-2.0 matches your intent. If the spec was
produced under a different contract or IP owner, either:

- Move it out of the repo before publishing, or
- Add a `SPEC-LICENSE` file with the actual rights the spec ships under.

Apache-2.0 covers code; specifications sometimes carry different terms.

## 9. Full-suite green

```sh
# One last confirm before push. See CONTRIBUTING.md for full commands.
cd gateway && go test ./...
cd control && pytest -q
cd detectors/pii     && pytest -q
cd detectors/llm_judge && pytest -q
cd detectors/safety  && pytest -q
cd detectors/nli     && pytest -q
cd automation        && pytest -q
cd console           && npm run typecheck
helm lint deploy/helm
```

If any suite is red, do not push — even to a private repo. First-pushed code
sets the reader's impression of quality.

## 10. First push mechanics

```sh
git init
git add .
# Look at what's staged. Should be N files (roughly 200-ish) but no secrets.
git status
git commit -m "Initial import: GuardX under Apache-2.0"

# Add remote (adjust org/name).
git branch -M main
git remote add origin git@github.com:your-org/guardx.git
git push -u origin main
```

## 11. Immediately after the first push

1. **Enable branch protection** on `main`: require PR reviews, require CI
   green, disallow force-push. GitHub → Settings → Branches → Add rule.
2. **Turn on security features**: Dependabot alerts + updates, secret scanning,
   push protection for secrets. GitHub → Settings → Security.
3. **Create a `SECURITY_CONTACT` in GitHub Advisory** so the private
   vulnerability report link works. GitHub → Security → Advisories → New
   draft advisory (dummy) → gets you the reporting UI live.
4. **Add topic tags**: `llm`, `guardrails`, `safety`, `pii`, `compliance`,
   `security`. Helps discoverability.
5. **Publish the SBOM** for the first release as a GitHub Release attachment.

## 12. What NOT to push

Reject the temptation to push:

- The `.env` (obviously).
- The `harness/fixtures/policy_doc.txt` if it contains real customer language.
- Any tenant identifiers from your Supabase URL (`eouchdiozzcexzknqvmq`
  currently appears in `.env`; not sensitive on its own but points at a
  specific project). Consider whether that's fine to expose.
- Anything in `sbom/` from a private build — attach to a release instead.

## References

- [SECURITY.md](../../SECURITY.md) — vulnerability reporting policy
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — contributor mechanics
- [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) — community standards
- [.gitignore](../../.gitignore) — canonical ignore list
