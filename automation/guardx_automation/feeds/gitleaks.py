"""Gitleaks-compatible pattern ingestor.

Reads a JSON ruleset (either from disk, a URL, or a mock in tests) and
proposes an additive extension of the tenant's `secretscan` guard config.

**Monotonic-add only.** This ingestor never modifies thresholds, actions, or
existing rule IDs — spec §3.3 says only monotonic_add proposals from feeds
are auto-approvable. If the source ever tries to change an existing rule ID's
regex, that's flagged as `change_class=scope_change` and requires a human.

The gateway's in-process secrets scanner reads rules.json at cold start;
adding new patterns to the *policy* is a small first step (the guard's
config lists rule ids). Full "ruleset hot-swap" lands when the ruleset itself
becomes a versioned artifact in the registry — deferred.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx

from ..client import ControlClient


class GitleaksFeedError(Exception):
    pass


@dataclass
class GitleaksProposal:
    added_rule_ids: list[str]
    submitted: bool
    proposal: dict[str, Any] | None
    reason: str


def _load_ruleset(source: str, http: httpx.Client) -> list[dict[str, Any]]:
    """Load a Gitleaks-shaped ruleset from URL or local path."""
    if source.startswith("http://") or source.startswith("https://"):
        r = http.get(source, timeout=15.0)
        r.raise_for_status()
        raw = r.text
    else:
        p = Path(source)
        if not p.exists():
            raise GitleaksFeedError(f"gitleaks ruleset not found: {p}")
        raw = p.read_text()
    try:
        doc = json.loads(raw)
    except Exception as e:
        raise GitleaksFeedError(f"invalid JSON: {e}") from e
    rules = doc.get("rules") if isinstance(doc, dict) else doc
    if not isinstance(rules, list):
        raise GitleaksFeedError("expected 'rules' array")
    return rules


def _rule_signature(rule: dict[str, Any]) -> str:
    """A stable signature so `same id + same regex` isn't proposed twice."""
    payload = json.dumps({"id": rule.get("id"), "regex": rule.get("regex")}, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def run_gitleaks_ingestor(
    tenant: str,
    policy_id: str,
    source: str,
    *,
    client: Optional[ControlClient] = None,
    http: Optional[httpx.Client] = None,
) -> GitleaksProposal:
    """One-shot ingestor. Returns a summary of what happened.

    Behavior:
      * Fetch the ruleset.
      * Find the current approved version of `policy_id` in the registry.
      * Diff its `g-secrets-*` guard.config.extra_rules against the fetched
        ruleset. Any rule id present in the source but missing in the policy
        is a candidate for addition (monotonic_add).
      * If the source contains a modified regex for an already-present rule
        id → mark scope_change (human approval required).
      * If there's nothing to add, no proposal is submitted.
    """
    client = client or ControlClient()
    http_client = http or httpx.Client(timeout=15.0)

    try:
        rules = _load_ruleset(source, http_client)
    finally:
        if http is None:
            http_client.close()

    versions = client.get_policy_versions(tenant, policy_id)
    approved = next(
        (v for v in versions if v["status"] == "approved"),
        None,
    )
    if not approved:
        return GitleaksProposal(
            added_rule_ids=[], submitted=False, proposal=None,
            reason=f"no approved version of {policy_id!r} — nothing to extend",
        )

    doc = copy.deepcopy(approved["document"])
    guards = (doc.get("spec") or {}).get("guards") or []
    secrets_guards = [g for g in guards if g.get("scenario") == "secrets"]
    if not secrets_guards:
        return GitleaksProposal(
            added_rule_ids=[], submitted=False, proposal=None,
            reason="policy has no secrets guard — nothing to extend",
        )

    # We stash added rules under guard.config.extra_rules; the gateway detector
    # will read them at bundle install. Existing rules.json in the binary stays
    # as the platform-shipped ruleset.
    added: list[str] = []
    change_class = "monotonic_add"
    for g in secrets_guards:
        cfg = g.setdefault("config", {})
        extra = cfg.setdefault("extra_rules", [])
        existing_ids: dict[str, dict[str, Any]] = {r["id"]: r for r in extra if r.get("id")}
        for rule in rules:
            rid = rule.get("id")
            if not rid:
                continue
            if rid in existing_ids:
                # A regex change to an existing id is *not* monotonic.
                if existing_ids[rid].get("regex") != rule.get("regex"):
                    change_class = "scope_change"
                continue
            extra.append(rule)
            added.append(rid)

    if not added:
        return GitleaksProposal(
            added_rule_ids=[], submitted=False, proposal=None,
            reason="ruleset offers no new rule ids for this tenant",
        )

    # Bump semver patch — automation always writes a new version.
    md = doc["metadata"]
    md["version"] = _bump_patch(md["version"])
    md["parent_version"] = approved["version"]
    md["status"] = "draft"
    md["origin"] = "feed"
    # Remove any lingering approved-by fields from the copy we cloned.
    for k in ("approved_by", "approved_at", "auto_approval_rule"):
        md.pop(k, None)

    origin_ref = {
        "feed": "gitleaks",
        "source": source,
        "ruleset_hash": _hash_source(rules),
        "added_rule_ids": added,
        "ts": int(time.time()),
    }
    result = client.submit_proposal(
        tenant=tenant,
        document=doc,
        origin="feed",
        change_class=change_class,
        origin_ref=origin_ref,
        change_note=f"gitleaks: +{len(added)} rules ({change_class})",
    )
    return GitleaksProposal(
        added_rule_ids=added,
        submitted=True,
        proposal=result,
        reason=(
            f"submitted {change_class} proposal with {len(added)} new rules; "
            + ("auto-approved" if result.get("auto_approved") else "awaiting human review")
        ),
    )


def _bump_patch(semver: str) -> str:
    parts = semver.split(".")
    if len(parts) != 3:
        return semver + ".1"
    major, minor, patch = parts
    try:
        return f"{major}.{minor}.{int(patch) + 1}"
    except ValueError:
        return semver + ".1"


def _hash_source(rules: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps([_rule_signature(r) for r in rules], sort_keys=True).encode()
    ).hexdigest()[:16]
