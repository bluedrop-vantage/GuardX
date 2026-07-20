"""LLM policy synthesizer (spec §5.2).

Pipeline:
  1. Chunk the input document into paragraphs with `(page, para)` anchors.
  2. Extract candidate rules per chunk via the LLM Judge and the
     `policy_synth@1.0.0` rubric (null-over-guess discipline enforced).
  3. Compile each mapped candidate into a policy `guards[]` entry using a
     scenario-specific default template and a severity → threshold table.
  4. Return the compiled draft policy + the human triage queue (candidates
     that came back with `scenario: null`).

Downstream (caller):
  * Runs the linter.
  * Submits as `origin=synthesizer, change_class=mixed` — never auto-approved.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from llm_judge import Judge, load_rubric


# ---- Severity → threshold table (reviewable artifact per §5.2) ----

_SEVERITY_TABLE: dict[str, dict[str, Any]] = {
    "low":    {"threshold": 0.85, "on_fail_override": None},
    "medium": {"threshold": 0.75, "on_fail_override": None},
    "high":   {"threshold": 0.65, "on_fail_override": "block"},
}


# ---- Detector templates per scenario ----

_TEMPLATES: dict[str, dict[str, Any]] = {
    "pii": {
        "detector": "presidio-ensemble@1.4.0",
        "config":   {"entity_pack": "financial-us@2.1", "language": "en"},
        "evidence": "spans",
    },
    "secrets": {
        "detector": "secretscan@0.1.0",
        "config":   {},
        "evidence": "spans",
    },
    "content_safety": {
        "detector": "safety-ensemble@1.3.0",
        "config":   {"rubric": "safety_llamaguard@1.0.0"},
        "evidence": "spans",
    },
    "hallucination": {
        "detector": "nli-groundedness@2.1.0",
        "config":   {"rubric": "nli_groundedness@1.0.0", "requires_context": True},
        "evidence": "spans",
    },
}


# ---- Chunking ----

_PARA_RE = re.compile(r"\n\s*\n")


def chunk_document(text: str, page: int = 1) -> list[dict[str, Any]]:
    """Split text into paragraph chunks with (page, para) anchors."""
    out: list[dict[str, Any]] = []
    idx = 0
    for para in _PARA_RE.split(text.strip()):
        para = para.strip()
        if not para:
            continue
        idx += 1
        out.append({"page": page, "para": idx, "text": para})
    return out


# ---- Extraction ----

@dataclass
class Candidate:
    rule_text: str
    source_anchor: dict[str, int]
    scenario: str | None
    direction: list[str]
    on_fail: str
    severity_hint: str
    notes: str = ""


@dataclass
class SynthResult:
    compiled_document: dict[str, Any]
    mapped: list[Candidate]
    triage: list[Candidate] = field(default_factory=list)   # scenario == null
    raw_chunks: list[dict[str, Any]] = field(default_factory=list)


async def extract_from_chunk(judge: Judge, chunk: dict[str, Any]) -> list[Candidate]:
    rubric = load_rubric("policy_synth@1.0.0")
    result = await judge.evaluate(
        rubric,
        chunk=chunk["text"],
        page=str(chunk["page"]),
        para=str(chunk["para"]),
    )
    parsed = result.parsed or {}
    raw = parsed.get("candidates", []) or []
    out: list[Candidate] = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        out.append(Candidate(
            rule_text=str(c.get("rule_text", "")).strip(),
            source_anchor=c.get("source_anchor") or {"page": chunk["page"], "para": chunk["para"]},
            scenario=c.get("scenario"),
            direction=list(c.get("direction") or ["output"]),
            on_fail=str(c.get("on_fail", "flag")),
            severity_hint=str(c.get("severity_hint", "medium")),
            notes=str(c.get("notes", "")).strip(),
        ))
    return out


# ---- Compilation ----

def _guard_id(scenario: str, index: int) -> str:
    # Policy guard-id regex disallows underscores → `content_safety` → `content-safety`.
    return f"g-synth-{scenario.replace('_', '-')}-{index:02d}"


def compile_guards(candidates: list[Candidate]) -> list[dict[str, Any]]:
    """Merge same-scenario candidates by direction. Simple v1: per scenario,
    per direction combination, we emit a single guard whose rule provenance
    lists every candidate's anchor + rule_text."""
    grouped: dict[tuple[str, tuple[str, ...]], list[Candidate]] = {}
    for c in candidates:
        if c.scenario not in _TEMPLATES:
            continue
        key = (c.scenario, tuple(sorted(c.direction)))
        grouped.setdefault(key, []).append(c)

    guards: list[dict[str, Any]] = []
    counter: dict[str, int] = {}
    for (scenario, direction), items in grouped.items():
        counter[scenario] = counter.get(scenario, 0) + 1
        tmpl = _TEMPLATES[scenario]
        highest = max(items, key=lambda c: _sev_rank(c.severity_hint))
        sev_row = _SEVERITY_TABLE[highest.severity_hint]
        on_fail = sev_row["on_fail_override"] or highest.on_fail
        guard = {
            "id": _guard_id(scenario, counter[scenario]),
            "scenario": scenario,
            "detector": tmpl["detector"],
            "direction": list(direction),
            "config": dict(tmpl["config"]),
            "threshold": sev_row["threshold"],
            "on_fail": on_fail,
            "evidence": tmpl["evidence"],
            # Provenance is where a reviewer sees why a guard exists.
            "provenance": [
                {"anchor": c.source_anchor, "rule_text": c.rule_text, "notes": c.notes}
                for c in items
            ],
        }
        guards.append(guard)
    return guards


def _sev_rank(sev: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(sev, 1)


def _base_policy(tenant: str, policy_id: str, apps: list[str],
                 environments: list[str]) -> dict[str, Any]:
    return {
        "apiVersion": "guardx/v1",
        "kind": "Policy",
        "metadata": {
            "id": policy_id,
            "version": "0.1.0",
            "tenant": tenant,
            "status": "draft",
            "origin": "synthesizer",
            "labels": {"synth": "policy_synth@1.0.0"},
        },
        "spec": {
            "applies_to": {"apps": apps, "environments": environments},
            "defaults": {"fail_mode": "closed", "timeout_ms": 12000},
            "guards": [],
        },
    }


async def synthesize(
    judge: Judge,
    text: str,
    *,
    tenant: str,
    policy_id: str,
    apps: list[str],
    environments: list[str],
    page: int = 1,
) -> SynthResult:
    """Run the full pipeline on `text`. `text` is the pre-extracted text of
    a compliance doc (PDF → text is left to the caller — see the API endpoint
    for the PDF adapter)."""
    chunks = chunk_document(text, page=page)
    all_candidates: list[Candidate] = []
    for c in chunks:
        got = await extract_from_chunk(judge, c)
        all_candidates.extend(got)

    mapped = [c for c in all_candidates if c.scenario in _TEMPLATES]
    triage = [c for c in all_candidates if c.scenario is None]

    doc = _base_policy(tenant, policy_id, apps, environments)
    doc["spec"]["guards"] = compile_guards(mapped)
    return SynthResult(compiled_document=doc, mapped=mapped, triage=triage,
                        raw_chunks=chunks)


# ---- PDF adapter (best-effort) ----

def read_pdf_or_text(path: Path) -> str:
    """Read plain text from a PDF (via PyPDF2) or a plain-text file.

    PDF text extraction is best-effort — heavy layout requires OCR / a
    proper adapter. This is a fine first pass for policy docs which are
    mostly linear prose.
    """
    if path.suffix.lower() == ".pdf":
        try:
            from PyPDF2 import PdfReader
        except ImportError as e:
            raise RuntimeError("PyPDF2 not installed") from e
        reader = PdfReader(str(path))
        return "\n\n".join(p.extract_text() or "" for p in reader.pages)
    return path.read_text()
