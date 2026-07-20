"""HTTP+JSON service implementing the guardx.detector.v1 contract for content
safety (spec §4.3.4).

Layer 1 is a keyword/heuristic fast path so cold-start doesn't hit the judge.
Layer 2 dispatches to whatever judge provider the rubric names — swappable
between hosted (Together, DeepInfra, OpenAI) and self-hosted (vLLM, Ollama)
via `config/providers.yaml`. Two rubric response formats are supported:

  * `json_object` — free-form rubric returning `{verdict, score, categories, reason}`
  * `llamaguard`  — native Meta Llama-Guard-3/4 protocol (`safe` or `unsafe\\nSn,Sn`)

Per-category thresholds live in `guard.config.category_thresholds` and are
applied here — that keeps policy (thresholds) and detector (raw scores)
cleanly split.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from llm_judge import Judge, load_rubric

from . import DETECTOR_ID, __version__

_judge: Judge | None = None


def _judge_singleton() -> Judge:
    global _judge
    if _judge is None:
        _judge = Judge.from_providers()
    return _judge


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
    metadata: dict[str, str] = Field(default_factory=dict)
    # Real-model round trips: 200 ms (Llama-Guard on DeepInfra) to 3 s
    # (Llama-3.3-70B on Together). Gateway sends the policy's timeout_ms
    # when it wants a tighter budget.
    deadline_ms: int = 10000


class CheckResponse(BaseModel):
    detector_version: str
    score: float
    verdict: str
    spans: list[SpanOut]
    explanation: str
    latency_ms: int
    categories: dict[str, float] = Field(default_factory=dict)
    provider: str = ""


class HealthResponse(BaseModel):
    detector_id: str
    detector_version: str
    status: str
    versions: dict[str, str]


app = FastAPI(title="GuardX Safety Detector", version=__version__)


# ---- Layer 1 fast-path heuristics ---------------------------------------

_HARD_SIGNALS: dict[str, list[str]] = {
    "self_harm":  ["how to end my life", "kill myself"],
    "weapons":    ["how to build a pipe bomb", "how to make a bomb"],
    "illegal":    ["how to launder money", "how to commit fraud"],
}


def layer1_predict(text: str) -> tuple[str | None, float]:
    lo = text.lower()
    for cat, needles in _HARD_SIGNALS.items():
        if any(n in lo for n in needles):
            return cat, 0.95
    return None, 0.0


# ---- Judge response parsers ---------------------------------------------

def _parse_llamaguard(raw: str) -> dict[str, Any]:
    """Parse Llama-Guard's two-line format:
        safe
      — or —
        unsafe
        S1,S9
    Returns the standard {verdict, score, categories, reason} shape.
    """
    lines = [ln.strip() for ln in raw.strip().splitlines() if ln.strip()]
    if not lines:
        return {"verdict": "PASS", "score": 0.0, "categories": {}, "reason": "empty"}
    verdict_line = lines[0].lower()
    if verdict_line.startswith("safe"):
        return {"verdict": "PASS", "score": 0.0, "categories": {}, "reason": "safe"}
    # unsafe path
    cats: dict[str, float] = {}
    if len(lines) >= 2:
        for tok in lines[1].split(","):
            tok = tok.strip().upper()
            if tok:
                cats[tok] = 1.0
    return {
        "verdict": "FAIL",
        "score": 1.0 if cats else 0.5,
        "categories": cats,
        "reason": "unsafe categories: " + ", ".join(sorted(cats)) if cats else "unsafe (no categories)",
    }


def _parse_by_format(response_format: str, raw: str, parsed: dict[str, Any] | None) -> dict[str, Any]:
    if response_format == "llamaguard":
        return _parse_llamaguard(raw)
    # json_object — trust the shim's parsed result.
    return parsed or {}


def _role_label(direction: str) -> str:
    # Meta's Llama-Guard treats User = input from human, Agent = model output.
    return "User" if direction.upper() == "INPUT" else "Agent"


# ---- HTTP routes --------------------------------------------------------

@app.get("/healthz", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        detector_id=DETECTOR_ID,
        detector_version=__version__,
        status="ok",
        versions={"detector": __version__},
    )


@app.post("/v1/check", response_model=CheckResponse)
async def check(req: CheckRequest) -> CheckResponse:
    start = time.perf_counter_ns()

    rubric_spec = req.config.get("rubric", "safety_llamaguard@1.0.0")
    rubric = load_rubric(rubric_spec)
    response_format = str(
        rubric.model.get("response_format")
        or rubric.extras.get("response_format", "json_object")
    ).lower()

    cat_thresholds: dict[str, float] = req.config.get("category_thresholds", {}) or {}

    # ---- Layer 1
    hard_cat, hard_score = layer1_predict(req.text)
    if hard_cat is not None:
        latency = int((time.perf_counter_ns() - start) / 1_000_000)
        return CheckResponse(
            detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
            score=hard_score,
            verdict="FAIL",
            spans=[SpanOut(start=0, end=len(req.text), label=hard_cat, confidence=hard_score)],
            explanation=f"layer1 heuristic matched category {hard_cat!r}",
            latency_ms=latency,
            categories={hard_cat: hard_score},
            provider="layer1",
        )

    # ---- Layer 2 (judge)
    judge = _judge_singleton()
    template_vars: dict[str, str] = {
        "text": req.text,
        "direction": req.direction,
        "role_label": _role_label(req.direction),
    }
    try:
        result = await asyncio.wait_for(
            judge.evaluate(rubric, **template_vars),
            timeout=max(1.0, (req.deadline_ms - 50) / 1000.0),
        )
    except asyncio.TimeoutError:
        latency = int((time.perf_counter_ns() - start) / 1_000_000)
        return CheckResponse(
            detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
            score=0.0, verdict="ERROR", spans=[],
            explanation="judge timeout", latency_ms=latency,
        )
    except Exception as e:
        latency = int((time.perf_counter_ns() - start) / 1_000_000)
        return CheckResponse(
            detector_version=f"{__version__}+rubric={rubric.id}@{rubric.version}",
            score=0.0, verdict="ERROR", spans=[],
            explanation=f"judge error: {type(e).__name__}: {e}",
            latency_ms=latency,
        )

    parsed = _parse_by_format(response_format, result.raw, result.parsed)
    categories: dict[str, float] = {
        k: float(v) for k, v in (parsed.get("categories") or {}).items()
    }
    score = float(parsed.get("score", 0.0))

    # Policy overrides model: apply per-category thresholds.
    fails = [(c, v) for c, v in categories.items() if v >= cat_thresholds.get(c, 0.5)]
    verdict = "FAIL" if fails else str(parsed.get("verdict", "PASS")).upper()
    if verdict not in {"PASS", "FAIL", "ERROR", "NEEDS_ESCALATION"}:
        verdict = "PASS"

    spans = [
        SpanOut(start=0, end=len(req.text), label=cat, confidence=v)
        for cat, v in fails
    ]

    latency = int((time.perf_counter_ns() - start) / 1_000_000)
    return CheckResponse(
        detector_version=(
            f"{__version__}+rubric={rubric.id}@{rubric.version}"
            f"+model={result.model}+provider={result.provider}"
        ),
        score=score,
        verdict=verdict,
        spans=spans,
        explanation=parsed.get("reason", "")[:200],
        latency_ms=latency,
        categories=categories,
        provider=result.provider,
    )
