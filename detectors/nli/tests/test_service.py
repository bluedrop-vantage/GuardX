import pytest
from fastapi.testclient import TestClient

import nli_detector.service as svc
from llm_judge import Judge, StubBackend


@pytest.fixture(autouse=True)
def stub_judge(monkeypatch):
    stub = StubBackend(
        name_str="together",
        responses={
            "claim was approved": {
                "supported": True, "score": 0.9,
                "evidence": "The claim was approved on July 10.", "confidence": 0.95,
            },
            "premium is $500": {
                "supported": True, "score": 0.85,
                "evidence": "Premium: $500/mo.", "confidence": 0.9,
            },
            "deductible is $2500": {
                "supported": False, "score": 0.1,
                "evidence": "", "confidence": 0.9,
            },
        }
    )
    monkeypatch.setattr(svc, "_judge", Judge(
        backends={"together": stub}, default_provider="together",
    ))


def _client():
    return TestClient(svc.app)


def test_ungroundable_when_no_context():
    r = _client().post("/v1/check", json={"text": "The claim was approved.", "context": []})
    body = r.json()
    assert body["verdict"] == "NEEDS_ESCALATION"
    assert "ungroundable" in body["explanation"]


def test_all_supported_passes():
    r = _client().post(
        "/v1/check",
        json={
            "text": "The claim was approved. The premium is $500 per month.",
            "context": [{"id": "policy", "text": "Premium: $500/mo. Claim: approved 2026-07-10."}],
        },
    )
    body = r.json()
    assert body["verdict"] == "PASS"
    assert body["score"] >= 0.5
    assert body["spans"] == []
    assert len(body["per_claim"]) == 2


def test_unsupported_claim_fails_and_spans_flagged():
    r = _client().post(
        "/v1/check",
        json={
            "text": "The claim was approved. The deductible is $2500.",
            "context": [{"id": "policy", "text": "Deductible: $250. Claim: approved."}],
        },
    )
    body = r.json()
    assert body["verdict"] == "FAIL"
    assert any(s["label"] == "ungrounded" for s in body["spans"])


def test_requires_context_false_lets_ungroundable_pass():
    r = _client().post(
        "/v1/check",
        json={
            "text": "hello",
            "context": [],
            "config": {"requires_context": False},
        },
    )
    body = r.json()
    assert body["verdict"] == "PASS"
