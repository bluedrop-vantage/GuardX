"""Invariant checks that don't require a live database.

Deeper end-to-end coverage is in `harness/m0_demo.sh` (spec §2 I1–I5).
"""
from __future__ import annotations

import pytest

from guardx_control.linter import Severity, lint_policy
from guardx_control.models import PolicyOrigin
from guardx_control.signing.canonical import canonical_json, sha256_hex


def _minimal_policy(status: str = "draft") -> dict:
    return {
        "apiVersion": "guardx/v1",
        "kind": "Policy",
        "metadata": {
            "id": "pii-fs",
            "version": "1.0.0",
            "tenant": "acme",
            "status": status,
            "created_by": "author@acme.com",
        },
        "spec": {
            "applies_to": {"apps": ["claims-bot"], "environments": ["prod"]},
            "defaults": {"fail_mode": "closed", "timeout_ms": 400},
            "guards": [
                {
                    "id": "g-pii-out",
                    "scenario": "pii",
                    "detector": "presidio-ensemble@1.4.0",
                    "direction": ["output"],
                    "threshold": 0.85,
                    "on_fail": "redact",
                    "evidence": "spans",
                }
            ],
        },
    }


def test_i1_document_hash_is_stable_over_key_order():
    """A signed bundle stakes its trust on hash equality across canonicalisers."""
    d1 = _minimal_policy()
    d2 = {**d1, "metadata": dict(reversed(list(d1["metadata"].items())))}
    assert sha256_hex(canonical_json(d1)) == sha256_hex(canonical_json(d2))


def test_i3_automation_origins_are_distinct_from_manual():
    """Route code hinges on this enum — a rename would break /v1/proposals."""
    assert PolicyOrigin.MANUAL.value == "manual"
    for automated in (PolicyOrigin.FEED, PolicyOrigin.SYNTHESIZER, PolicyOrigin.AUTOTUNER):
        assert automated.value != PolicyOrigin.MANUAL.value


def test_i5_missing_fail_mode_is_blocking_error():
    doc = _minimal_policy()
    del doc["spec"]["defaults"]["fail_mode"]
    errs = [i for i in lint_policy(doc) if i.severity is Severity.ERROR]
    assert any(i.code == "fail_mode.missing" for i in errs), errs
