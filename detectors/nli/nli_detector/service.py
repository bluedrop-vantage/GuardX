"""HTTP+JSON service for the NLI groundedness detector.

Per spec §4.3.3 the aggregate score is the min over claims (weakest-claim
gating) so a single unsupported claim can drop the verdict. Each claim comes
with its own span (offset within the answer text) so the gateway can render
per-claim highlights.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from llm_judge import Judge, load_rubric

from . import DETECTOR_ID, __version__
from .segmenter import claims


_judge: Judge | None = None


def _judge_singleton() -> Judge:
    global _judge
    if _judge is None:
        _judge = Judge.from_providers()
    return _judge


class ContextDoc(BaseModel):
    id: str = ""
    text: str
    source: str = ""


class SpanOut(BaseModel):
    start: int
    end: int
    label: str
    confidence: float


class CheckRequest(BaseModel):
    request_id: str = ""
    text: str
    direction: str = "OUTPUT"
    config: dict[str, Any] = Field(default_factory=dict)
    context: list[ContextDoc] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    # Hosted judge per claim; whole-answer budget scales with claim count.
    deadline_ms: int = 15000


class CheckResponse(BaseModel):
    detector_version: str
    score: float
    verdict: str
    spans: list[SpanOut]
    explanation: str
    latency_ms: int
    per_claim: list[dict[str, Any]] = Field(default_factory=list)


app = FastAPI(title="GuardX NLI Groundedness Detector", version=__version__)


@app.get("/healthz")
def health() -> dict:
    return {"detector_id": DETECTOR_ID, "detector_version": __version__, "status": "ok"}


@app.post("/v1/check", response_model=CheckResponse)
async def check(req: CheckRequest) -> CheckResponse:
    t0 = time.perf_counter_ns()
    rubric_spec = req.config.get("rubric", "nli_groundedness@1.0.0")
    requires_context: bool = bool(req.config.get("requires_context", True))
    rubric = load_rubric(rubric_spec)

    context_text = "\n\n".join(f"[{c.id or 'doc'}] {c.text}" for c in req.context).strip()

    if not context_text:
        latency = int((time.perf_counter_ns() - t0) / 1_000_000)
        if requires_context:
            return CheckResponse(
                detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
                score=0.0, verdict="NEEDS_ESCALATION",
                spans=[], explanation="ungroundable: no context supplied",
                latency_ms=latency,
            )
        # Otherwise pass through — nothing to check.
        return CheckResponse(
            detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
            score=0.0, verdict="PASS", spans=[],
            explanation="no context; requires_context=false",
            latency_ms=latency,
        )

    segments = claims(req.text)
    if not segments:
        latency = int((time.perf_counter_ns() - t0) / 1_000_000)
        return CheckResponse(
            detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
            score=1.0, verdict="PASS", spans=[],
            explanation="no verifiable claims found",
            latency_ms=latency,
        )

    judge = _judge_singleton()
    deadline_s = max(1.0, (req.deadline_ms - 50) / 1000.0)

    async def _score(claim: str) -> dict[str, Any]:
        try:
            r = await asyncio.wait_for(
                judge.evaluate(rubric, context=context_text, claim=claim),
                timeout=deadline_s,
            )
            p = r.parsed
            return {
                "claim": claim,
                "supported": bool(p.get("supported", False)),
                "score": float(p.get("score", 0.0)),
                "evidence": p.get("evidence", "")[:200],
                "confidence": float(p.get("confidence", 0.0)),
                "error": None,
            }
        except Exception as e:  # noqa: BLE001
            return {
                "claim": claim, "supported": False, "score": 0.0,
                "evidence": "", "confidence": 0.0, "error": str(e),
            }

    per_claim = await asyncio.gather(*[_score(c) for c in segments])

    # Weakest-claim aggregate. Spans point to claim positions inside `text`.
    scores = [pc["score"] for pc in per_claim]
    agg = min(scores) if scores else 1.0

    spans: list[SpanOut] = []
    cursor = 0
    for pc in per_claim:
        # Find the claim in the source text starting from cursor.
        idx = req.text.find(pc["claim"], cursor)
        if idx < 0:
            idx = req.text.find(pc["claim"])
        if idx >= 0:
            end = idx + len(pc["claim"])
            cursor = end
            if not pc["supported"]:
                spans.append(SpanOut(
                    start=idx, end=end,
                    label="ungrounded", confidence=1.0 - pc["score"],
                ))

    threshold = float(req.config.get("threshold", 0.5))
    # Verdict rules:
    #   any unsupported claim → FAIL (this is the strict interpretation)
    #   OR weakest score below threshold → FAIL
    strict = any(not pc["supported"] for pc in per_claim)
    verdict = "FAIL" if (strict or agg < threshold) else "PASS"

    weakest = min(per_claim, key=lambda pc: pc["score"]) if per_claim else None
    reason = (
        f"{sum(1 for pc in per_claim if not pc['supported'])}/{len(per_claim)} unsupported; "
        f"weakest claim scored {weakest['score']:.2f}"
        if weakest else "no claims"
    )

    latency = int((time.perf_counter_ns() - t0) / 1_000_000)
    return CheckResponse(
        detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
        score=agg,
        verdict=verdict,
        spans=spans,
        explanation=reason,
        latency_ms=latency,
        per_claim=per_claim,
    )
