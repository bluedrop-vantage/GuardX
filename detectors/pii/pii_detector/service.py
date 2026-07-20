"""HTTP+JSON transport for the detector contract (proto/detector.proto).

Real gRPC is a drop-in swap: message shapes are identical, only the wire
encoding changes. Kept HTTP for M1 to skip protoc tooling.
"""
from __future__ import annotations

import time
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import DETECTOR_ID, __version__
from .detector import score, scan
from .entity_pack import load_pack


class CheckRequest(BaseModel):
    request_id: str = ""
    text: str
    direction: str = "OUTPUT"
    config: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, str] = Field(default_factory=dict)
    deadline_ms: int = 400


class SpanOut(BaseModel):
    start: int
    end: int
    label: str
    confidence: float


class CheckResponse(BaseModel):
    detector_version: str
    score: float
    verdict: str
    spans: list[SpanOut]
    explanation: str
    latency_ms: int


class HealthResponse(BaseModel):
    detector_id: str
    detector_version: str
    status: str
    versions: dict[str, str]


app = FastAPI(title="GuardX PII Detector", version=__version__)


@app.get("/healthz", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        detector_id=DETECTOR_ID,
        detector_version=__version__,
        status="ok",
        versions={"detector": __version__},
    )


@app.post("/v1/check", response_model=CheckResponse)
def check(req: CheckRequest) -> CheckResponse:
    start = time.perf_counter_ns()
    entity_pack_spec = req.config.get("entity_pack", "financial-us@2.1")
    pack = load_pack(entity_pack_spec)
    spans = scan(req.text, pack)
    latency_ms = int((time.perf_counter_ns() - start) / 1_000_000)
    s = score(spans)
    verdict = "FAIL" if s > 0 else "PASS"
    return CheckResponse(
        detector_version=__version__,
        score=s,
        verdict=verdict,
        spans=[SpanOut(**sp.as_dict()) for sp in spans],
        explanation=_explain(spans, pack),
        latency_ms=latency_ms,
    )


def _explain(spans, pack) -> str:
    if not spans:
        return "no PII entities matched"
    labels = ", ".join(sorted({s.label for s in spans}))
    return f"pack={pack.pack_id}@{pack.version} matched: {labels}"
