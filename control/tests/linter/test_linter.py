import copy

import pytest

from guardx_control.linter import Severity, lint_policy


BASE = {
    "apiVersion": "guardx/v1",
    "kind": "Policy",
    "metadata": {
        "id": "pii-financial-services",
        "version": "1.0.0",
        "tenant": "acme",
        "status": "draft",
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


def _errors(issues):
    return [i for i in issues if i.severity is Severity.ERROR]


def test_baseline_clean():
    assert _errors(lint_policy(copy.deepcopy(BASE))) == []


def test_pii_full_text_evidence_is_error():
    doc = copy.deepcopy(BASE)
    doc["spec"]["guards"][0]["evidence"] = "full_text"
    codes = [i.code for i in _errors(lint_policy(doc))]
    assert "pii.full_text_evidence" in codes


def test_verify_live_in_prod_is_error():
    doc = copy.deepcopy(BASE)
    doc["spec"]["guards"].append(
        {
            "id": "g-secrets-out",
            "scenario": "secrets",
            "detector": "secretscan@2.0.1",
            "direction": ["output"],
            "config": {"verify_live": True},
            "threshold": 1.0,
            "on_fail": "block",
        }
    )
    codes = [i.code for i in _errors(lint_policy(doc))]
    assert "secrets.verify_live_prod" in codes


def test_missing_fail_mode_is_error():
    doc = copy.deepcopy(BASE)
    del doc["spec"]["defaults"]["fail_mode"]
    codes = [i.code for i in _errors(lint_policy(doc))]
    assert "fail_mode.missing" in codes


def test_schema_shape_violation_short_circuits():
    doc = copy.deepcopy(BASE)
    doc["spec"]["guards"][0]["scenario"] = "not-a-real-scenario"
    issues = lint_policy(doc)
    errs = _errors(issues)
    assert errs and all(e.code == "schema.invalid" for e in errs)
