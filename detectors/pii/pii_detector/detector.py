"""Ensemble scoring: Layer 1 (regex) + Layer 3 (context words)."""
from __future__ import annotations

from dataclasses import dataclass

from . import validators
from .entity_pack import Entity, EntityPack


@dataclass
class Span:
    start: int
    end: int
    label: str
    confidence: float

    def as_dict(self) -> dict:
        return {
            "start": self.start,
            "end": self.end,
            "label": self.label,
            "confidence": round(self.confidence, 3),
        }


CONTEXT_RADIUS = 40
CONTEXT_BOOST = 0.20


def _context_hit(text: str, start: int, end: int, words: list[str]) -> bool:
    if not words:
        return False
    lo = max(0, start - CONTEXT_RADIUS)
    hi = min(len(text), end + CONTEXT_RADIUS)
    window = text[lo:hi].lower()
    return any(w in window for w in words)


def scan_entity(text: str, ent: Entity) -> list[Span]:
    spans: list[Span] = []
    for m in ent.pattern.finditer(text):
        match = m.group(0)
        if not all(validators.run(v, match) for v in ent.validators):
            continue
        start, end = m.span()
        conf = ent.base_confidence
        has_ctx = _context_hit(text, start, end, ent.context_words)
        if has_ctx:
            conf = min(1.0, conf + CONTEXT_BOOST)
        if ent.requires_context and not has_ctx:
            continue
        spans.append(Span(start=start, end=end, label=ent.label, confidence=conf))
    return spans


def scan(text: str, pack: EntityPack) -> list[Span]:
    """Run all recognizers in the pack; return non-overlapping spans."""
    all_spans: list[Span] = []
    for ent in pack.entities:
        all_spans.extend(scan_entity(text, ent))
    return _dedup_overlaps(all_spans)


def _dedup_overlaps(spans: list[Span]) -> list[Span]:
    if len(spans) < 2:
        return spans
    # Sort by start; on overlap keep higher-confidence (then longer).
    spans.sort(key=lambda s: (s.start, -s.confidence, -(s.end - s.start)))
    out: list[Span] = []
    for s in spans:
        if out and s.start < out[-1].end:
            if s.confidence > out[-1].confidence:
                out[-1] = s
            continue
        out.append(s)
    return out


def score(spans: list[Span]) -> float:
    return max((s.confidence for s in spans), default=0.0)
