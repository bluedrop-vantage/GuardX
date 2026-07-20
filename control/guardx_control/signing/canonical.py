"""RFC 8785 JSON Canonicalization Scheme (JCS).

Produces a byte-for-byte deterministic JSON encoding so signatures reproduce
across environments. Rules:
  - object members lexicographically sorted by key (as UTF-16 code units)
  - no insignificant whitespace
  - strings JSON-escaped per RFC 8259
  - numbers per ECMA-262 7.1.12.1 "Number to String" (implemented via a
    conservative subset: integers use int repr; floats route through the same
    algorithm that Python's json.dumps applies for canonicality here — spec
    numbers in policies are integers/plain floats, so this covers our domain).
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def _canon(value: Any) -> Any:
    if isinstance(value, dict):
        # sort keys per code-unit order (Python str compare matches UTF-16 order
        # for the BMP characters we use in policy documents).
        return {k: _canon(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_canon(v) for v in value]
    # RFC 8785 numbers follow ECMA-262 Number.prototype.toString: `0.0` → `"0"`.
    # Python's json.dumps emits `"0.0"` for a float; normalize integer-valued
    # floats to ints so both sides agree byte-for-byte with the Go canonicaliser.
    if isinstance(value, float) and not isinstance(value, bool):
        # bool is a subclass of int; exclude it from the numeric branch.
        if value != value:              # NaN
            raise ValueError("canonical_json: NaN is not JSON-representable")
        if value == float("inf") or value == float("-inf"):
            raise ValueError("canonical_json: Infinity is not JSON-representable")
        if value.is_integer() and -1e15 <= value <= 1e15:
            return int(value)
    return value


def canonical_json(document: Any) -> bytes:
    """Return canonical UTF-8 bytes per RFC 8785 for the given JSON-serialisable value."""
    canon = _canon(document)
    return json.dumps(
        canon,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
        sort_keys=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
