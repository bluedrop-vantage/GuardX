"""Per-(tenant, app) hash chain (spec §4.4).

Each event embeds `prev_event_hash`, then computes its own `event_hash` over a
canonical subset of its fields. Verification walks the chain and reproduces
each hash; any insert, delete, or edit breaks the chain and is detectable.

The canonical-field list is deliberately explicit: extra fields added later
must NOT change the hash of old events. Never reorder or remove entries.
"""
from __future__ import annotations

import hashlib
from typing import Any

from ..signing.canonical import canonical_json


# Committed field set — order does NOT matter (canonical_json sorts) but the
# set does. Adding a field here would silently change verdicts for old data.
CHAIN_FIELDS: tuple[str, ...] = (
    "event_id",
    "ts",              # ISO-8601 UTC
    "tenant",
    "app",
    "env",
    "chain_seq",
    "request_id",
    "policy",
    "bundle_seq",
    "guard_id",
    "scenario",
    "detector",
    "direction",
    "verdict",
    "score",
    "action_taken",
    "latency_ms",
    "evidence_mode",
    "spans",
    "text_hash",
    "prev_event_hash",
)


def canonical_event_bytes(event: dict[str, Any]) -> bytes:
    """Return canonical bytes for the chain-covered subset of an event."""
    subset = {k: event.get(k) for k in CHAIN_FIELDS}
    return canonical_json(subset)


def compute_event_hash(event: dict[str, Any]) -> str:
    """Return `sha256:<hex>` over the canonical subset."""
    data = canonical_event_bytes(event)
    return "sha256:" + hashlib.sha256(data).hexdigest()
