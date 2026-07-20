"""Data-minimization gate.

Every event carries an `evidence_mode` from the guard config (spec §4.4):

    none       hashes-only — drop spans + payload
    spans      offsets + labels — no text (default; PII policies mandated to this)
    full_text  encrypted payload stored via payload_ref (M2 lands schema; the
               encrypted-payload writer + per-tenant KMS envelope land in M3)

The Control API applies this on ingest as a defense in depth: even if the
gateway emitter forgets to gate, the store won't retain more than policy
allows.
"""
from __future__ import annotations

from typing import Any


def minimize_event(event: dict[str, Any]) -> dict[str, Any]:
    mode = event.get("evidence_mode") or "spans"
    out = dict(event)
    if mode == "none":
        out["spans"] = None
        out["payload_ref"] = None
    elif mode == "spans":
        out["payload_ref"] = None
        # `spans` is preserved (offset/label only — never the source text).
    elif mode == "full_text":
        # Enforced schema constraint: spans + payload_ref both allowed.
        pass
    return out
