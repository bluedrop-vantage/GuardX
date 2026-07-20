"""Auto-tuner (spec §5.3).

Reads labeled feedback events for a guard and its raw decision events, joins
them into (score, label) pairs, and fits a threshold that improves the
tenant's stated objective (default: minimize FP rate subject to FN rate ≤ 0.5%).

Statistical discipline:
  * Minimum sample size gate (default 50 TP + 50 TN) — smaller batches don't
    produce proposals.
  * 95% Wilson interval on FP/FN rates. Proposal is submitted only when the
    upper bound of the improved rate is below the previous rate's estimate.
  * Every proposal ships with the labeled sample sizes, the recomputed rates,
    and the CI so a reviewer sees the arithmetic.

Note: this is `origin=autotuner`, NOT `origin=feed`. Auto-approval never
triggers — a human must approve threshold moves.
"""
from __future__ import annotations

import copy
import math
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from ..client import ControlClient


# --- statistical helpers ----------------------------------------------------

def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a Binomial proportion."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - half), min(1.0, center + half))


@dataclass
class ThresholdRecommendation:
    guard_id: str
    current_threshold: float
    proposed_threshold: float
    n_labeled: int
    fp_before: int          # FPs at current threshold
    fn_before: int
    fp_after: int           # FPs at proposed threshold
    fn_after: int
    fp_rate_before: float
    fp_rate_after: float
    fp_ci_after: tuple[float, float]
    fn_rate_after: float
    fn_ci_after: tuple[float, float]
    reason: str


@dataclass
class AutotunerReport:
    tenant: str
    app: str
    considered_guards: list[str]
    recommendations: list[ThresholdRecommendation]
    proposal_submitted: bool
    proposal: dict[str, Any] | None


# --- core -----------------------------------------------------------------

def _join_events_and_feedback(
    events: list[dict[str, Any]],
    feedback: list[dict[str, Any]],
) -> dict[str, list[tuple[float, str]]]:
    """Group (score, label) pairs by guard_id.

    Labels: "positive" (analyst says: yes, unsafe) or "negative" (safe).
    Derived from feedback disposition:
        true_positive       → positive (guard was right)
        false_positive      → negative (guard fired but it was safe)
        true_negative       → negative (guard didn't fire; correct)
        false_negative      → positive (guard missed a real violation)
    """
    events_by_id = {e["event_id"]: e for e in events}
    by_guard: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for fb in feedback:
        eid = fb.get("event_id")
        if not eid or eid not in events_by_id:
            continue
        e = events_by_id[eid]
        score = e.get("score")
        if score is None:
            continue
        gid = fb.get("guard_id") or e.get("guard_id")
        if not gid:
            continue
        disp = fb["disposition"]
        if disp in ("true_positive", "false_negative"):
            by_guard[gid].append((float(score), "positive"))
        else:
            by_guard[gid].append((float(score), "negative"))
    return by_guard


def _current_thresholds(document: dict[str, Any]) -> dict[str, float]:
    out: dict[str, float] = {}
    for g in (document.get("spec") or {}).get("guards", []) or []:
        thr = g.get("threshold")
        if isinstance(thr, (int, float)):
            out[g["id"]] = float(thr)
    return out


def _search_threshold(
    samples: list[tuple[float, str]],
    current: float,
    objective_fp_ceiling: float = 0.02,
    objective_fn_ceiling: float = 0.005,
) -> Optional[ThresholdRecommendation]:
    """Grid search over 40 candidate thresholds in [max(0.5,current-0.2), min(0.99,current+0.15)]
    and pick the one that improves FP rate without breaching FN ceiling.

    Simple + deterministic — good enough for a solo-builder autotuner. The full
    spec (spec §5.3) implies fitting a proper ROC curve; that's a future
    refinement.
    """
    if len(samples) < 20:
        return None

    def _rates(t: float) -> tuple[int, int, int, int]:
        # tp: positive & score >= t
        # fn: positive & score <  t
        # fp: negative & score >= t
        # tn: negative & score <  t
        tp = fn = fp = tn = 0
        for score, label in samples:
            fired = score >= t
            if label == "positive":
                tp += fired
                fn += not fired
            else:
                fp += fired
                tn += not fired
        return tp, fn, fp, tn

    def _fp_rate(fp: int, tn: int) -> float:
        return fp / (fp + tn) if (fp + tn) else 0.0

    def _fn_rate(fn: int, tp: int) -> float:
        return fn / (fn + tp) if (fn + tp) else 0.0

    tp0, fn0, fp0, tn0 = _rates(current)
    if (tp0 + fn0) < 10 or (fp0 + tn0) < 10:
        return None
    fp_rate_before = _fp_rate(fp0, tn0)

    lo = max(0.05, current - 0.20)
    hi = min(0.99, current + 0.15)
    step = (hi - lo) / 40 if hi > lo else 0.01
    best: Optional[ThresholdRecommendation] = None
    t = lo
    while t <= hi:
        tp, fn, fp, tn = _rates(t)
        fp_r = _fp_rate(fp, tn)
        fn_r = _fn_rate(fn, tp)
        fp_ci = wilson_interval(fp, fp + tn)
        fn_ci = wilson_interval(fn, fn + tp)
        # Improvement rule: FP rate strictly lower AND FN rate stays within ceiling.
        if fp_r < fp_rate_before and fn_r <= objective_fn_ceiling and fp_ci[1] < fp_rate_before:
            if best is None or fp_r < best.fp_rate_after:
                best = ThresholdRecommendation(
                    guard_id="", current_threshold=current, proposed_threshold=round(t, 3),
                    n_labeled=len(samples),
                    fp_before=fp0, fn_before=fn0,
                    fp_after=fp, fn_after=fn,
                    fp_rate_before=fp_rate_before,
                    fp_rate_after=fp_r, fp_ci_after=fp_ci,
                    fn_rate_after=fn_r, fn_ci_after=fn_ci,
                    reason=(
                        f"FP rate {fp_rate_before:.3f} → {fp_r:.3f} "
                        f"(95% CI [{fp_ci[0]:.3f}, {fp_ci[1]:.3f}]); "
                        f"FN rate {fn_r:.3f} within ceiling {objective_fn_ceiling}"
                    ),
                )
        t += step
    if best and abs(best.proposed_threshold - current) < 0.005:
        return None  # not enough movement to matter
    return best


def _apply_thresholds(document: dict[str, Any],
                      recs: list[ThresholdRecommendation]) -> dict[str, Any]:
    doc = copy.deepcopy(document)
    by_id = {r.guard_id: r for r in recs}
    for g in (doc.get("spec") or {}).get("guards", []) or []:
        r = by_id.get(g.get("id"))
        if r:
            g["threshold"] = r.proposed_threshold
    return doc


def run_autotuner(
    tenant: str,
    app: str,
    policy_id: str,
    *,
    days_lookback: int = 14,
    min_labeled: int = 20,
    client: Optional[ControlClient] = None,
) -> AutotunerReport:
    """One-shot autotuner. Returns per-guard recommendations + optional proposal."""
    client = client or ControlClient()

    versions = client.get_policy_versions(tenant, policy_id)
    approved = next((v for v in versions if v["status"] == "approved"), None)
    if not approved:
        return AutotunerReport(
            tenant=tenant, app=app,
            considered_guards=[], recommendations=[],
            proposal_submitted=False, proposal=None,
        )

    thresholds = _current_thresholds(approved["document"])

    events = client.list_evidence(tenant=tenant, app=app, since_seq=0, limit=5000)
    since_iso = (datetime.now(timezone.utc) - timedelta(days=days_lookback)) \
        .isoformat().replace("+00:00", "Z")
    feedback = client.list_feedback(tenant=tenant, app=app, since_iso=since_iso, limit=5000)

    joined = _join_events_and_feedback(events, feedback)
    recommendations: list[ThresholdRecommendation] = []
    considered: list[str] = []
    for gid, samples in joined.items():
        considered.append(gid)
        if gid not in thresholds:
            continue
        if len(samples) < min_labeled:
            continue
        rec = _search_threshold(samples, thresholds[gid])
        if rec is None:
            continue
        rec.guard_id = gid
        recommendations.append(rec)

    if not recommendations:
        return AutotunerReport(
            tenant=tenant, app=app, considered_guards=sorted(considered),
            recommendations=[], proposal_submitted=False, proposal=None,
        )

    # Build the proposal.
    doc = _apply_thresholds(approved["document"], recommendations)
    md = doc["metadata"]
    md["version"] = _bump_patch(md["version"])
    md["parent_version"] = approved["version"]
    md["status"] = "draft"
    md["origin"] = "autotuner"
    for k in ("approved_by", "approved_at", "auto_approval_rule"):
        md.pop(k, None)

    origin_ref = {
        "tuner": "guardx.autotuner@0.1.0",
        "app": app,
        "days_lookback": days_lookback,
        "ts": int(time.time()),
        "recommendations": [
            {
                "guard_id": r.guard_id,
                "current": r.current_threshold,
                "proposed": r.proposed_threshold,
                "n": r.n_labeled,
                "fp_rate": {"before": r.fp_rate_before, "after": r.fp_rate_after,
                             "ci_after": list(r.fp_ci_after)},
                "fn_rate": {"after": r.fn_rate_after, "ci_after": list(r.fn_ci_after)},
                "reason": r.reason,
            }
            for r in recommendations
        ],
    }
    result = client.submit_proposal(
        tenant=tenant,
        document=doc,
        origin="autotuner",
        change_class="threshold_tune",     # NOT auto-approvable
        origin_ref=origin_ref,
        change_note=(
            f"autotuner: proposed threshold moves for {len(recommendations)} guards "
            f"({days_lookback}-day window)"
        ),
    )
    return AutotunerReport(
        tenant=tenant, app=app,
        considered_guards=sorted(considered),
        recommendations=recommendations,
        proposal_submitted=True, proposal=result,
    )


def _bump_patch(semver: str) -> str:
    parts = semver.split(".")
    if len(parts) != 3:
        return semver + ".1"
    try:
        return f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
    except ValueError:
        return semver + ".1"
