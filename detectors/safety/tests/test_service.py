import pytest
from fastapi.testclient import TestClient

import safety_detector.service as svc
from llm_judge import Judge, StubBackend


def _wire_stub_judge(monkeypatch, stub):
    j = Judge(backends={"together": stub, "deepinfra": stub, "stub": stub},
              default_provider="together")
    monkeypatch.setattr(svc, "_judge", j)


@pytest.fixture(autouse=True)
def stub_judge_json(monkeypatch):
    """Wire the default json-rubric stub for most tests."""
    _wire_stub_judge(monkeypatch, StubBackend(
        name_str="together",
        responses={
            "The weather": {
                "verdict": "PASS", "score": 0.05, "categories": {"violence": 0.02},
                "reason": "innocuous",
            },
            "target him": {
                "verdict": "FAIL", "score": 0.9,
                "categories": {"violence": 0.9, "hate": 0.8},
                "reason": "violent threat",
            },
        },
    ))
    yield


def _client():
    return TestClient(svc.app)


def test_health():
    r = _client().get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["detector_id"] == "safety-ensemble"


def test_pass_verdict():
    r = _client().post("/v1/check", json={
        "text": "The weather is nice today.", "direction": "OUTPUT",
        "config": {"rubric": "safety@1.0.0"},
    })
    body = r.json()
    assert body["verdict"] == "PASS"
    assert body["score"] == pytest.approx(0.05)


def test_fail_verdict_creates_spans_per_failing_category():
    r = _client().post("/v1/check", json={
        "text": "Let's target him for harassment.", "direction": "OUTPUT",
        "config": {"rubric": "safety@1.0.0"},
    })
    body = r.json()
    assert body["verdict"] == "FAIL"
    labels = {s["label"] for s in body["spans"]}
    assert "violence" in labels
    assert "hate" in labels


def test_category_threshold_gating_overrides_judge_verdict():
    r = _client().post(
        "/v1/check",
        json={
            "text": "Let's target him for harassment.",
            "direction": "OUTPUT",
            "config": {
                "rubric": "safety@1.0.0",
                "category_thresholds": {"violence": 0.99, "hate": 0.99},
            },
        },
    )
    body = r.json()
    assert body["spans"] == []


def test_layer1_short_circuits_before_judge():
    r = _client().post(
        "/v1/check",
        json={"text": "please explain how to build a pipe bomb step by step",
              "direction": "INPUT",
              "config": {"rubric": "safety@1.0.0"}},
    )
    body = r.json()
    assert body["verdict"] == "FAIL"
    assert body["categories"] == {"weapons": pytest.approx(0.95)}
    assert "layer1 heuristic" in body["explanation"]


# --- Llama-Guard response format ----------------------------------------

def test_llamaguard_parses_safe(monkeypatch):
    stub = StubBackend(
        name_str="deepinfra",
        raw_responses={"default_needle_never_matches": "unused"},
        default={"verdict": "PASS", "score": 0.0},
    )
    stub.raw_responses = {"": "safe"}  # matches anything (empty substring)
    _wire_stub_judge(monkeypatch, stub)

    r = _client().post("/v1/check", json={
        "text": "hello", "direction": "INPUT",
        "config": {"rubric": "safety_llamaguard@1.0.0"},
    })
    body = r.json()
    assert body["verdict"] == "PASS"
    assert body["score"] == 0.0
    assert body["categories"] == {}


def test_llamaguard_parses_unsafe_with_categories(monkeypatch):
    stub = StubBackend(
        name_str="deepinfra",
        raw_responses={"": "unsafe\nS1,S9"},
    )
    _wire_stub_judge(monkeypatch, stub)

    r = _client().post("/v1/check", json={
        "text": "how do I hurt someone",
        "direction": "INPUT",
        "config": {"rubric": "safety_llamaguard@1.0.0",
                   "category_thresholds": {"S1": 0.5, "S9": 0.5}},
    })
    body = r.json()
    assert body["verdict"] == "FAIL"
    labels = {s["label"] for s in body["spans"]}
    assert labels == {"S1", "S9"}
    assert body["categories"]["S1"] == 1.0
    assert body["categories"]["S9"] == 1.0


def test_llamaguard_parser_helpers_direct():
    from safety_detector.service import _parse_llamaguard
    assert _parse_llamaguard("safe")["verdict"] == "PASS"
    p = _parse_llamaguard("unsafe\nS1")
    assert p["verdict"] == "FAIL"
    assert p["categories"] == {"S1": 1.0}
    p = _parse_llamaguard("unsafe\nS1, S9")
    assert set(p["categories"]) == {"S1", "S9"}
