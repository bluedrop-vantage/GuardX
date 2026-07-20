"""Unit tests for the LLM synthesizer. Uses the StubBackend so no network."""
from __future__ import annotations

import json
import pytest

from guardx_automation.synthesizer import chunk_document, compile_guards, synthesize
from guardx_automation.synthesizer.synth import Candidate
from llm_judge import Judge, StubBackend


def _stub_judge(payloads: dict[str, dict]) -> Judge:
    stub = StubBackend(
        name_str="together",
        responses={k: v for k, v in payloads.items()},
        default={"candidates": []},
    )
    return Judge(backends={"together": stub}, default_provider="together")


def test_chunker_splits_paragraphs():
    text = "First para.\n\nSecond para line 1.\nStill second.\n\nThird."
    chunks = chunk_document(text, page=1)
    assert len(chunks) == 3
    assert chunks[0]["para"] == 1
    assert chunks[1]["para"] == 2
    assert chunks[2]["para"] == 3


def test_compile_guards_groups_by_scenario_direction():
    cs = [
        Candidate(rule_text="No SSN in output",
                  source_anchor={"page": 1, "para": 1},
                  scenario="pii", direction=["output"],
                  on_fail="redact", severity_hint="high"),
        Candidate(rule_text="Also PII redaction on input",
                  source_anchor={"page": 1, "para": 3},
                  scenario="pii", direction=["output"],
                  on_fail="flag", severity_hint="medium"),
    ]
    guards = compile_guards(cs)
    assert len(guards) == 1
    g = guards[0]
    assert g["scenario"] == "pii"
    # High severity wins → on_fail=block override, threshold=0.65
    assert g["on_fail"] == "block"
    assert g["threshold"] == 0.65
    assert len(g["provenance"]) == 2


@pytest.mark.asyncio
async def test_synthesize_end_to_end_with_stub():
    text = (
        "Do not disclose social security numbers in customer replies.\n\n"
        "The system must not generate advice about specific investments.\n\n"
        "This is a general purpose overview."
    )
    payloads = {
        "social security": {
            "candidates": [{
                "rule_text": "Do not disclose social security numbers",
                "source_anchor": {"page": 1, "para": 1},
                "scenario": "pii", "direction": ["output"],
                "on_fail": "redact", "severity_hint": "high",
                "notes": "PHI/PII on outbound only",
            }],
        },
        "advice about specific": {
            "candidates": [{
                "rule_text": "No specific investment advice",
                "source_anchor": {"page": 1, "para": 2},
                "scenario": "content_safety", "direction": ["output"],
                "on_fail": "block", "severity_hint": "high",
                "notes": "Financial advice tone",
            }],
        },
        "general purpose": {
            "candidates": [{
                "rule_text": "This is a general purpose overview",
                "source_anchor": {"page": 1, "para": 3},
                "scenario": None, "direction": ["output"],
                "on_fail": "flag", "severity_hint": "low",
                "notes": "no actionable rule",
            }],
        },
    }
    judge = _stub_judge(payloads)
    result = await synthesize(
        judge=judge, text=text,
        tenant="acme-fs", policy_id="synth-demo",
        apps=["claims-bot"], environments=["prod"],
    )
    # Two mapped, one triaged.
    assert len(result.mapped) == 2
    assert len(result.triage) == 1
    # Compiled document has 2 guards, one per scenario.
    doc = result.compiled_document
    scenarios = sorted(g["scenario"] for g in doc["spec"]["guards"])
    assert scenarios == ["content_safety", "pii"]
    # Metadata is stamped.
    assert doc["metadata"]["origin"] == "synthesizer"
    assert doc["metadata"]["tenant"] == "acme-fs"
