"""Unit tests for the Gitleaks feed ingestor. Uses a fake ControlClient."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from guardx_automation.feeds import run_gitleaks_ingestor


class FakeControl:
    def __init__(self, versions: list[dict[str, Any]]):
        self.versions = versions
        self.proposals: list[dict[str, Any]] = []

    def get_policy_versions(self, tenant: str, policy_id: str):
        return self.versions

    def submit_proposal(self, tenant: str, document, origin, change_class=None,
                        origin_ref=None, change_note=None):
        rec = {
            "tenant": tenant, "document": document, "origin": origin,
            "change_class": change_class, "origin_ref": origin_ref,
            "change_note": change_note,
        }
        self.proposals.append(rec)
        return {"policy": {"policy_id": document["metadata"]["id"], "version": document["metadata"]["version"], "status": "approved"},
                "lint": [], "auto_approved": True,
                "auto_approval_rule": "AA-1"}


def _approved_policy(rules_already_present: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "policy_id": "pii-fs", "version": "1.0.0", "status": "approved",
        "origin": "manual", "created_by": "author@acme.com", "created_at": "2026-07-16T00:00:00Z",
        "document_hash": "sha256:0",
        "document": {
            "apiVersion": "guardx/v1", "kind": "Policy",
            "metadata": {"id": "pii-fs", "version": "1.0.0", "tenant": "acme", "status": "approved"},
            "spec": {
                "applies_to": {"apps": ["a"], "environments": ["prod"]},
                "defaults": {"fail_mode": "closed", "timeout_ms": 400},
                "guards": [
                    {"id": "g-secrets-io", "scenario": "secrets",
                     "detector": "secretscan@0.1.0", "direction": ["input", "output"],
                     "config": {"extra_rules": rules_already_present or []},
                     "threshold": 0.9, "on_fail": "block"},
                ],
            },
        },
    }


def _write_ruleset(tmp_path: Path, rules: list[dict[str, Any]]) -> str:
    p = tmp_path / "rs.json"
    p.write_text(json.dumps({"rules": rules}))
    return str(p)


def test_no_approved_policy_yields_no_proposal(tmp_path):
    control = FakeControl(versions=[])
    src = _write_ruleset(tmp_path, [{"id": "aws-key", "regex": r"\bAKIA[A-Z0-9]{16}\b"}])
    out = run_gitleaks_ingestor("acme", "pii-fs", src, client=control)
    assert not out.submitted
    assert "no approved" in out.reason


def test_new_rule_is_monotonic_add_and_auto_approved(tmp_path):
    control = FakeControl(versions=[_approved_policy()])
    src = _write_ruleset(tmp_path, [
        {"id": "aws-new", "regex": r"\bAKIA[A-Z0-9]{16}\b"},
        {"id": "aws-new-2", "regex": r"\bASIA[A-Z0-9]{16}\b"},
    ])
    out = run_gitleaks_ingestor("acme", "pii-fs", src, client=control)
    assert out.submitted
    assert set(out.added_rule_ids) == {"aws-new", "aws-new-2"}
    submitted = control.proposals[0]
    assert submitted["origin"] == "feed"
    assert submitted["change_class"] == "monotonic_add"


def test_regex_change_on_existing_id_flips_to_scope_change(tmp_path):
    control = FakeControl(versions=[
        _approved_policy(rules_already_present=[{"id": "aws-key", "regex": r"\bAKIA[A-Z0-9]{16}\b"}])
    ])
    src = _write_ruleset(tmp_path, [
        {"id": "aws-key", "regex": r"\bAKIA[A-Z0-9]{20}\b"},   # changed
        {"id": "brand-new", "regex": r"\bXYZ[A-Z]+\b"},
    ])
    out = run_gitleaks_ingestor("acme", "pii-fs", src, client=control)
    assert out.submitted
    assert out.added_rule_ids == ["brand-new"]                # only the additive
    assert control.proposals[0]["change_class"] == "scope_change"


def test_all_rules_already_present_yields_no_proposal(tmp_path):
    rules = [{"id": "aws-key", "regex": r"\bAKIA[A-Z0-9]{16}\b"}]
    control = FakeControl(versions=[_approved_policy(rules_already_present=rules)])
    src = _write_ruleset(tmp_path, rules)
    out = run_gitleaks_ingestor("acme", "pii-fs", src, client=control)
    assert not out.submitted
    assert "no new" in out.reason
