"""Inheritance engine tests — proves that baseline ⊕ industry ⊕ app compose
in the documented order, override tracking captures divergence at leaf level,
and guards merge by id."""
from __future__ import annotations

from guardx_control.profiles import compile_policy, load_pack, merge, OverrideTrace


def test_baseline_pack_loads():
    pack = load_pack("baseline@1.0.0")
    assert pack.id == "baseline"
    assert pack.version == "1.0.0"
    assert any(g["id"] == "g-secrets-io" for g in pack.document["spec"]["guards"])


def test_hipaa_compiles_over_baseline():
    doc, trace = compile_policy(
        tenant_slug="acme-health",
        profile_spec="hipaa@1.0.0",
        app_policy=None,
    )
    guards = {g["id"]: g for g in doc["spec"]["guards"]}
    # hipaa provides g-pii-io (direction=[input,output], healthcare-us pack)
    assert "g-pii-io" in guards
    assert guards["g-pii-io"]["config"]["entity_pack"] == "healthcare-us@1.0"
    # baseline's g-pii-out is still there (hipaa didn't override that id)
    assert "g-pii-out" in guards
    # override trace credits hipaa for adding g-pii-io.
    assert len(trace.entries) > 0
    assert any(
        e["layer"] == "hipaa@1.0.0" and "g-pii-io" in e["path"]
        for e in trace.entries
    )


def test_glba_narrower_hallucination_threshold_wins():
    doc, trace = compile_policy(
        tenant_slug="acme-fs",
        profile_spec="glba-nydfs@1.0.0",
        app_policy=None,
    )
    guards = {g["id"]: g for g in doc["spec"]["guards"]}
    assert guards["g-halluc-out"]["threshold"] == 0.8
    assert guards["g-halluc-out"]["on_fail"] == "block_and_explain"
    # trace should record that the threshold came from glba-nydfs.
    assert any(
        e["layer"].startswith("glba-nydfs") and "g-halluc-out" in e["path"]
        for e in trace.entries
    )


def test_app_policy_override_of_industry_wins():
    """An app can tighten thresholds — but the override is recorded."""
    app_layer = {
        "spec": {
            "applies_to": {"apps": ["claims-bot"], "environments": ["prod"]},
            "guards": [
                {"id": "g-halluc-out", "threshold": 0.9, "on_fail": "block"},
            ],
        }
    }
    doc, trace = compile_policy(
        tenant_slug="acme-fs",
        profile_spec="glba-nydfs@1.0.0",
        app_policy=app_layer,
    )
    guards = {g["id"]: g for g in doc["spec"]["guards"]}
    assert guards["g-halluc-out"]["threshold"] == 0.9
    assert guards["g-halluc-out"]["on_fail"] == "block"
    assert any(
        e["layer"] == "app-policy" and "threshold" in e["path"]
        for e in trace.entries
    )


def test_guard_remove_marker_drops_guard():
    """A child can explicitly remove a parent guard via __remove__ marker."""
    app_layer = {
        "spec": {
            "applies_to": {"apps": ["a"], "environments": ["dev"]},
            "guards": [
                {"id": "g-halluc-out", "__remove__": True},
            ],
        }
    }
    doc, trace = compile_policy(
        tenant_slug="acme",
        profile_spec="baseline@1.0.0",
        app_policy=app_layer,
    )
    ids = {g["id"] for g in doc["spec"]["guards"]}
    assert "g-halluc-out" not in ids


def test_merge_records_deep_overrides():
    trace = OverrideTrace()
    parent = {"spec": {"defaults": {"fail_mode": "closed", "timeout_ms": 400}}}
    child = {"spec": {"defaults": {"timeout_ms": 800}}}
    out = merge(parent, child,
                parent_layer="baseline", child_layer="app",
                trace=trace)
    assert out["spec"]["defaults"]["fail_mode"] == "closed"
    assert out["spec"]["defaults"]["timeout_ms"] == 800
    assert any(e["path"] == "spec.defaults.timeout_ms" for e in trace.entries)


def test_compile_stamps_tenant_and_profile():
    doc, _ = compile_policy(
        tenant_slug="acme-fs",
        profile_spec="glba-nydfs@1.0.0",
        app_policy={
            "metadata": {"id": "claims-bot-policy", "version": "1.0.0"},
            "spec": {"applies_to": {"apps": ["claims-bot"], "environments": ["prod"]}},
        },
    )
    assert doc["metadata"]["tenant"] == "acme-fs"
    assert doc["metadata"]["profile"] == "glba-nydfs@1.0.0"
    assert doc["metadata"]["id"] == "claims-bot-policy"
    assert "parent" not in doc["metadata"]
