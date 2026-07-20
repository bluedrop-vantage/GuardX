"""Claim segmentation (spec §4.3.3).

Split answer text into candidate claims. M3 first-pass:
  1. Sentence split (regex over . ! ? followed by whitespace + capital, with
     abbreviation guards for Mr., Dr., U.S., etc.)
  2. Conjunction split — break "X, and Y" into two claims when both sides
     are propositional (contains a verb-like token).

Not linguistically rigorous — this is a fast pre-tokenizer. A dedicated
segmenter (spaCy / pysbd) is a future upgrade.
"""
from __future__ import annotations

import re

_ABBREVS = {"mr.", "mrs.", "ms.", "dr.", "sr.", "jr.", "st.", "u.s.", "u.k.",
            "e.g.", "i.e.", "etc.", "vs.", "no.", "fig.", "inc.", "ltd."}

# Sentence boundary: [.!?] then whitespace then either capital letter, digit,
# or open-quote. Negative lookbehind guards common abbreviations further down.
_SENT_BOUNDARY = re.compile(r"([.!?])\s+(?=[A-Z0-9\"'\(])")

# Coord-conjunction split — used only when both halves look propositional.
# Very conservative: only splits at ", and " / ", but ".
_CONJ_SPLIT = re.compile(r",\s+(?:and|but)\s+", re.IGNORECASE)


def _looks_propositional(chunk: str) -> bool:
    """Rough test: does the chunk contain a verb-ish token?

    Not linguistic — checks for auxiliary verbs / common tense markers.
    Missing them → probably a noun phrase, don't split.
    """
    return bool(re.search(
        r"\b(is|are|was|were|has|have|had|does|do|did|will|would|can|could|may|might|shall|should|must|be|been|being)\b",
        chunk, re.IGNORECASE,
    )) or bool(re.search(r"\b\w+(?:ed|ing|s)\b", chunk))


def sentences(text: str) -> list[str]:
    """Split on sentence boundaries with abbreviation guards."""
    if not text.strip():
        return []
    # Naive boundary split, then rejoin any pair where the LHS ends with an
    # abbreviation from the guard list.
    parts = _SENT_BOUNDARY.split(text.strip())
    # After split, parts alternate: chunk, punctuation, chunk, punctuation, chunk...
    # Reassemble into sentences (chunk + its trailing punct).
    sents: list[str] = []
    i = 0
    while i < len(parts):
        chunk = parts[i]
        punct = parts[i + 1] if i + 1 < len(parts) else ""
        merged = (chunk + punct).strip()
        if merged:
            sents.append(merged)
        i += 2
    # Merge abbreviation splits: if a sentence ends with an abbrev, join it
    # with the next.
    merged_sents: list[str] = []
    for s in sents:
        last = s.split()[-1].lower() if s.split() else ""
        if merged_sents and merged_sents[-1].split()[-1].lower() in _ABBREVS:
            merged_sents[-1] = merged_sents[-1] + " " + s
        else:
            merged_sents.append(s)
    return merged_sents


def claims(text: str) -> list[str]:
    """Segment text into claim candidates: sentences → coord-split → strip."""
    out: list[str] = []
    for s in sentences(text):
        if _CONJ_SPLIT.search(s):
            parts = [p.strip() for p in _CONJ_SPLIT.split(s) if p.strip()]
            if len(parts) > 1 and all(_looks_propositional(p) for p in parts):
                out.extend(parts)
                continue
        out.append(s.strip())
    # Filter empties and very short fragments (< 3 words) — those aren't
    # verifiable claims.
    return [c for c in out if len(c.split()) >= 3]
