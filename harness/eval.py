#!/usr/bin/env python3
"""Golden-set evaluation harness.

Runs the local PII detector against a labeled corpus and prints precision /
recall / F1 per label plus totals. Used to gate policy promotions in M4+;
in M1 we invoke it manually to prove the ≥0.95 precision target.

Usage:
    python harness/eval.py --pack financial-us@2.1 --set harness/golden/financial_us.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def _add_pii_path() -> None:
    # Make detectors/pii importable when run from the repo root.
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "detectors" / "pii"))


def load_corpus(path: Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", default="financial-us@2.1")
    ap.add_argument("--set", dest="set_path", required=True, type=Path)
    ap.add_argument("--min-precision", type=float, default=0.95)
    args = ap.parse_args()

    _add_pii_path()
    from pii_detector.detector import scan
    from pii_detector.entity_pack import load_pack

    pack = load_pack(args.pack)
    corpus = load_corpus(args.set_path)

    tp = Counter()
    fp = Counter()
    fn = Counter()

    per_case: list[dict] = []
    for case in corpus:
        expected = set(case.get("expected_labels", []))
        spans = scan(case["text"], pack)
        detected = {s.label for s in spans}
        for lab in expected & detected:
            tp[lab] += 1
        for lab in detected - expected:
            fp[lab] += 1
        for lab in expected - detected:
            fn[lab] += 1
        per_case.append({
            "text": case["text"][:80],
            "expected": sorted(expected),
            "detected": sorted(detected),
        })

    labels = sorted(set(tp) | set(fp) | set(fn))
    def _rate(a, b):
        return (a / b) if b else 1.0

    print(f"{'label':20} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>6} {'rec':>6} {'F1':>6}")
    total_tp = total_fp = total_fn = 0
    for lab in labels:
        p = _rate(tp[lab], tp[lab] + fp[lab])
        r = _rate(tp[lab], tp[lab] + fn[lab])
        f1 = _rate(2 * p * r, p + r) if (p + r) else 0.0
        print(f"{lab:20} {tp[lab]:>4} {fp[lab]:>4} {fn[lab]:>4} {p:>6.3f} {r:>6.3f} {f1:>6.3f}")
        total_tp += tp[lab]; total_fp += fp[lab]; total_fn += fn[lab]
    prec = _rate(total_tp, total_tp + total_fp)
    rec = _rate(total_tp, total_tp + total_fn)
    f1 = _rate(2 * prec * rec, prec + rec) if (prec + rec) else 0.0
    print(f"{'TOTAL':20} {total_tp:>4} {total_fp:>4} {total_fn:>4} {prec:>6.3f} {rec:>6.3f} {f1:>6.3f}")

    if prec < args.min_precision:
        print(f"\nFAIL: precision {prec:.3f} below threshold {args.min_precision}")
        print("Details:", json.dumps(per_case, indent=2))
        return 1
    print(f"\nOK: precision {prec:.3f} >= {args.min_precision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
