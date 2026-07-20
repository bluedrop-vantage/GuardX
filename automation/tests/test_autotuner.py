"""Unit tests for the autotuner. Uses a fake ControlClient."""
from __future__ import annotations

from typing import Any

from guardx_automation.autotuner import run_autotuner
from guardx_automation.autotuner.tuner import wilson_interval


class FakeControl:
    def __init__(self, policy: dict[str, Any], events: list[dict[str, Any]],
                 feedback: list[dict[str, Any]]):
        self.policy_versions = [policy] if policy else []
        self.events = events
        self.feedback = feedback
        self.proposals: list[dict[str, Any]] = []

    def get_policy_versions(self, tenant, policy_id):
        return self.policy_versions

    def list_evidence(self, tenant, app, since_seq=0, limit=5000):
        return self.events

    def list_feedback(self, tenant, app=None, guard_id=None, since_iso=None, limit=5000):
        return self.feedback

    def submit_proposal(self, tenant, document, origin, change_class=None,
                        origin_ref=None, change_note=None):
        rec = {"origin": origin, "change_class": change_class,
                "origin_ref": origin_ref, "document": document}
        self.proposals.append(rec)
        return {"policy": {"policy_id": document["metadata"]["id"], "version": document["metadata"]["version"]},
                "auto_approved": False, "auto_approval_rule": None, "lint": []}


def _policy(threshold: float = 0.7) -> dict[str, Any]:
    return {
        "policy_id": "p1", "version": "1.0.0", "status": "approved",
        "origin": "manual", "created_by": "a@x", "created_at": "2026-07-01T00:00:00Z",
        "document_hash": "sha256:0",
        "document": {
            "apiVersion": "guardx/v1", "kind": "Policy",
            "metadata": {"id": "p1", "version": "1.0.0", "tenant": "acme", "status": "approved"},
            "spec": {
                "applies_to": {"apps": ["bot"], "environments": ["prod"]},
                "defaults": {"fail_mode": "closed", "timeout_ms": 400},
                "guards": [
                    {"id": "g-pii-out", "scenario": "pii",
                     "detector": "presidio-ensemble@1.4.0", "direction": ["output"],
                     "threshold": threshold, "on_fail": "redact"},
                ],
            },
        },
    }


def _mk(events: list[tuple[str, float, str]]) -> tuple[list, list]:
    """Build (events, feedback) lists from (event_id, score, disposition) triples."""
    evs, fbs = [], []
    for i, (eid, score, disp) in enumerate(events):
        evs.append({
            "event_id": eid, "ts": "2026-07-15T00:00:00Z", "tenant": "acme", "app": "bot",
            "env": "prod", "chain_seq": i + 1, "request_id": f"r-{i}", "policy": "p1@1.0.0",
            "bundle_seq": 1, "guard_id": "g-pii-out", "scenario": "pii",
            "detector": "presidio-ensemble@1.4.0", "direction": "output",
            "verdict": "FAIL" if score >= 0.7 else "PASS", "score": score,
            "action_taken": None, "latency_ms": 10,
            "evidence_mode": "spans", "spans": None, "text_hash": "sha256:0",
            "prev_event_hash": None, "event_hash": "sha256:x", "is_shadow": False,
        })
        fbs.append({"tenant": "acme", "app": "bot", "event_id": eid,
                    "guard_id": "g-pii-out", "policy": "p1@1.0.0",
                    "source": "analyst", "disposition": disp, "note": None,
                    "submitted_by": "a@x", "at": "2026-07-15T00:00:00Z", "id": i + 1})
    return evs, fbs


def test_wilson_ci_reasonable():
    lo, hi = wilson_interval(5, 100)
    assert 0 < lo < hi < 1
    # tighter interval with more data.
    lo2, hi2 = wilson_interval(50, 1000)
    assert (hi2 - lo2) < (hi - lo)


def test_no_labels_yields_no_recommendation():
    control = FakeControl(policy=_policy(), events=[], feedback=[])
    report = run_autotuner("acme", "bot", "p1", client=control)
    assert report.recommendations == []
    assert not report.proposal_submitted


def test_high_fp_at_current_threshold_gets_tightened():
    """Craft samples so at threshold=0.7 FP rate is high; at higher threshold FP rate drops."""
    # 60 negatives with scores clustered around 0.7-0.75  (raising threshold drops FPs)
    # 60 positives with scores 0.85+                       (raising threshold doesn't lose any)
    triples: list[tuple[str, float, str]] = []
    for i in range(60):
        triples.append((f"neg{i}", 0.72 + (i % 5) * 0.005, "false_positive"))
    for i in range(60):
        triples.append((f"pos{i}", 0.88 + (i % 4) * 0.02, "true_positive"))
    events, fb = _mk(triples)
    control = FakeControl(policy=_policy(threshold=0.7), events=events, feedback=fb)
    report = run_autotuner("acme", "bot", "p1", client=control, min_labeled=20)
    assert report.recommendations, "expected a threshold recommendation"
    rec = report.recommendations[0]
    assert rec.proposed_threshold > 0.7
    # Proposal actually submitted.
    assert report.proposal_submitted
    assert control.proposals[0]["origin"] == "autotuner"
    assert control.proposals[0]["change_class"] == "threshold_tune"


def test_below_min_labeled_yields_no_recommendation():
    triples: list[tuple[str, float, str]] = []
    for i in range(5):
        triples.append((f"neg{i}", 0.72, "false_positive"))
    events, fb = _mk(triples)
    control = FakeControl(policy=_policy(), events=events, feedback=fb)
    report = run_autotuner("acme", "bot", "p1", client=control, min_labeled=20)
    assert report.recommendations == []
