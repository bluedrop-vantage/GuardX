"""Chain-hash invariants (no DB required)."""
from __future__ import annotations

from guardx_control.evidence.chain import CHAIN_FIELDS, compute_event_hash
from guardx_control.evidence.minimizer import minimize_event


def _event(**overrides) -> dict:
    base = {
        "event_id": "e1",
        "ts": "2026-07-16T10:00:00Z",
        "tenant": "acme", "app": "claims-bot", "env": "prod",
        "chain_seq": 1,
        "request_id": "r-1",
        "policy": "pii-fs@1.0.0", "bundle_seq": 1,
        "guard_id": "g-pii-out", "scenario": "pii",
        "detector": "presidio-ensemble@1.4.0", "direction": "output",
        "verdict": "FAIL", "score": 0.95,
        "action_taken": "redact", "latency_ms": 18,
        "evidence_mode": "spans",
        "spans": [{"start": 7, "end": 18, "label": "SSN", "confidence": 0.95}],
        "text_hash": "sha256:aaaa",
        "prev_event_hash": None,
    }
    base.update(overrides)
    return base


def test_event_hash_is_stable_across_field_order():
    e1 = _event()
    e2 = {k: e1[k] for k in reversed(list(e1))}
    assert compute_event_hash(e1) == compute_event_hash(e2)


def test_event_hash_changes_when_verdict_flips():
    a = compute_event_hash(_event(verdict="PASS"))
    b = compute_event_hash(_event(verdict="FAIL"))
    assert a != b


def test_event_hash_ignores_uncovered_fields():
    """A new (non-committed) field must not disturb the chain of old events."""
    a = compute_event_hash(_event())
    b = compute_event_hash(_event(new_experimental_field="whatever"))
    assert a == b


def test_chain_fields_list_is_frozen():
    # A safety net against silent additions/reorderings that would break
    # verification of old anchors.
    assert CHAIN_FIELDS == (
        "event_id", "ts", "tenant", "app", "env", "chain_seq", "request_id",
        "policy", "bundle_seq", "guard_id", "scenario", "detector", "direction",
        "verdict", "score", "action_taken", "latency_ms", "evidence_mode",
        "spans", "text_hash", "prev_event_hash",
    )


def test_minimize_none_drops_spans():
    e = minimize_event(_event(evidence_mode="none"))
    assert e["spans"] is None
    assert e["payload_ref"] is None


def test_minimize_spans_preserves_spans():
    e = minimize_event(_event(evidence_mode="spans"))
    assert e["spans"] and e["spans"][0]["label"] == "SSN"
    assert e["payload_ref"] is None


def test_ecma262_integer_valued_float_serializes_as_int():
    """Ensures 0.0 hashes to the same bytes as 0 (§4.4 chain interop with Go)."""
    a = compute_event_hash(_event(score=0.0))
    b = compute_event_hash(_event(score=0))
    assert a == b
