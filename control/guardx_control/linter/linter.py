"""Policy linter — static checks over a Policy document.

Runs at draft time (Control API) and again as part of bundle build. Some rules
carry over to runtime as gateway invariants (e.g. `verify_live` in prod).

Spec §7 rules covered:
  * contradictory guards
  * streaming-incompatible actions (block_and_explain on a streaming policy)
  * missing fail_mode (neither guard nor policy default supplies one)
  * evidence_mode=full_text under a PII policy
  * verify_live in prod
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, List, Optional

import jsonschema

from ..config import get_settings


class Severity(str, Enum):
    ERROR = "error"      # blocks submit/approve
    WARN = "warn"        # surfaced but non-blocking
    INFO = "info"


@dataclass(frozen=True)
class LinterIssue:
    code: str
    severity: Severity
    message: str
    path: str = ""

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
        }


@lru_cache(maxsize=1)
def _policy_schema() -> dict:
    schemas_dir = get_settings().schemas_dir
    return json.loads((schemas_dir / "policy.schema.json").read_text())


def validate_schema(document: dict) -> List[LinterIssue]:
    issues: List[LinterIssue] = []
    validator = jsonschema.Draft202012Validator(_policy_schema())
    for err in sorted(validator.iter_errors(document), key=lambda e: list(e.path)):
        issues.append(
            LinterIssue(
                code="schema.invalid",
                severity=Severity.ERROR,
                message=err.message,
                path=".".join(str(p) for p in err.path),
            )
        )
    return issues


def _guards(spec: dict) -> Iterable[dict]:
    return spec.get("guards", []) or []


def _default_fail_mode(spec: dict) -> Optional[str]:
    return (spec.get("defaults") or {}).get("fail_mode")


def _envs(spec: dict) -> List[str]:
    return (spec.get("applies_to") or {}).get("environments", []) or []


def _rule_missing_fail_mode(spec: dict) -> Iterable[LinterIssue]:
    default = _default_fail_mode(spec)
    for g in _guards(spec):
        if g.get("fail_mode") is None and default is None:
            yield LinterIssue(
                code="fail_mode.missing",
                severity=Severity.ERROR,
                message=(
                    f"guard {g.get('id')} has no fail_mode and policy defaults.fail_mode is unset. "
                    "Per spec §2 invariant I5, fail behavior is never a hardcoded default."
                ),
                path=f"spec.guards.{g.get('id')}",
            )


def _rule_verify_live_in_prod(spec: dict) -> Iterable[LinterIssue]:
    envs = _envs(spec)
    if "prod" not in envs:
        return
    for g in _guards(spec):
        if g.get("scenario") != "secrets":
            continue
        cfg = g.get("config") or {}
        if cfg.get("verify_live"):
            yield LinterIssue(
                code="secrets.verify_live_prod",
                severity=Severity.ERROR,
                message=(
                    f"guard {g.get('id')}: verify_live=true is disallowed in prod policies "
                    "(exfil risk — spec §4.3.2)."
                ),
                path=f"spec.guards.{g.get('id')}.config.verify_live",
            )


def _rule_full_text_evidence_under_pii(spec: dict) -> Iterable[LinterIssue]:
    for g in _guards(spec):
        if g.get("scenario") != "pii":
            continue
        if g.get("evidence") == "full_text":
            yield LinterIssue(
                code="pii.full_text_evidence",
                severity=Severity.ERROR,
                message=(
                    f"guard {g.get('id')}: evidence=full_text is prohibited on PII guards. "
                    "The evidence system must not become the leak (spec §4.4)."
                ),
                path=f"spec.guards.{g.get('id')}.evidence",
            )


def _rule_streaming_incompatible_actions(spec: dict) -> Iterable[LinterIssue]:
    labels: dict[str, Any] = spec.get("labels") or {}
    streaming = bool((spec.get("defaults") or {}).get("streaming")) or (
        str(labels.get("streaming", "")).lower() == "true"
    )
    if not streaming:
        return
    for g in _guards(spec):
        if g.get("on_fail") == "block_and_explain":
            yield LinterIssue(
                code="streaming.block_and_explain",
                severity=Severity.WARN,
                message=(
                    f"guard {g.get('id')}: block_and_explain under streaming is downgraded "
                    "to end-of-stream retraction (spec §4.2)."
                ),
                path=f"spec.guards.{g.get('id')}.on_fail",
            )


def _rule_contradictory_guards(spec: dict) -> Iterable[LinterIssue]:
    """Two guards on the same scenario+direction with conflicting on_fail actions."""
    by_key: dict[tuple[str, str], list[dict]] = {}
    for g in _guards(spec):
        for d in g.get("direction", []):
            by_key.setdefault((g.get("scenario"), d), []).append(g)
    for (scen, direction), gs in by_key.items():
        if len(gs) < 2:
            continue
        actions = {g.get("on_fail") for g in gs}
        blocking = {"block", "block_and_explain"}
        if actions & blocking and actions - blocking:
            ids = ", ".join(g["id"] for g in gs)
            yield LinterIssue(
                code="guards.contradictory",
                severity=Severity.WARN,
                message=(
                    f"multiple {scen} guards on {direction} have conflicting actions ({actions}). "
                    f"Only the strictest wins at runtime — review: {ids}."
                ),
                path="spec.guards",
            )


def lint_policy(document: dict) -> List[LinterIssue]:
    """Full lint pass. Returns all issues; caller decides on severity gating."""
    issues = validate_schema(document)
    # Schema failure short-circuits deeper rules (they assume a valid shape).
    if any(i.severity is Severity.ERROR for i in issues):
        return issues
    spec = document.get("spec") or {}
    for rule in (
        _rule_missing_fail_mode,
        _rule_verify_live_in_prod,
        _rule_full_text_evidence_under_pii,
        _rule_streaming_incompatible_actions,
        _rule_contradictory_guards,
    ):
        issues.extend(rule(spec))
    return issues
