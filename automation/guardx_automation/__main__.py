"""CLI entry point for the automation plane.

Usage:
  # One-shot runs (useful for demos / cron-outside-python):
  python -m guardx_automation feed-gitleaks --tenant acme --policy pii-fs --source ./gitleaks.json
  python -m guardx_automation autotune     --tenant acme --app claims-bot --policy pii-fs
  python -m guardx_automation synthesize   --tenant acme --policy synth-demo --apps claims-bot --input ./policy.txt

  # Long-running scheduler (production):
  python -m guardx_automation scheduler --config ./config/automation.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .autotuner import run_autotuner
from .client import ControlClient
from .feeds import run_gitleaks_ingestor
from .scheduler import run_scheduler
from .synthesizer import synthesize
from .synthesizer.synth import read_pdf_or_text


def _cmd_feed(args: argparse.Namespace) -> int:
    out = run_gitleaks_ingestor(
        tenant=args.tenant,
        policy_id=args.policy,
        source=args.source,
    )
    print(json.dumps({
        "submitted": out.submitted,
        "added_rule_ids": out.added_rule_ids,
        "reason": out.reason,
    }, indent=2))
    return 0 if out.submitted else 0


def _cmd_autotune(args: argparse.Namespace) -> int:
    report = run_autotuner(
        tenant=args.tenant, app=args.app, policy_id=args.policy,
        days_lookback=args.days_lookback, min_labeled=args.min_labeled,
    )
    print(json.dumps({
        "considered_guards": report.considered_guards,
        "recommendations": [
            {
                "guard_id": r.guard_id,
                "current": r.current_threshold,
                "proposed": r.proposed_threshold,
                "n": r.n_labeled,
                "fp_before": r.fp_rate_before,
                "fp_after": r.fp_rate_after,
                "fp_ci_after": r.fp_ci_after,
                "reason": r.reason,
            }
            for r in report.recommendations
        ],
        "proposal_submitted": report.proposal_submitted,
    }, indent=2))
    return 0


def _cmd_synthesize(args: argparse.Namespace) -> int:
    from llm_judge import Judge
    text = read_pdf_or_text(Path(args.input))
    judge = Judge.from_providers()
    result = asyncio.run(synthesize(
        judge=judge, text=text,
        tenant=args.tenant, policy_id=args.policy,
        apps=args.apps.split(","),
        environments=args.envs.split(","),
    ))
    # Submit as a draft proposal (never auto-approved for synthesizer).
    client = ControlClient()
    resp = client.submit_proposal(
        tenant=args.tenant,
        document=result.compiled_document,
        origin="synthesizer",
        change_class="mixed",
        origin_ref={
            "synthesizer": "guardx.synthesizer@0.1.0",
            "input_file": args.input,
            "mapped": len(result.mapped),
            "triage": len(result.triage),
        },
        change_note=(
            f"synthesized {len(result.mapped)} guards; "
            f"{len(result.triage)} items sent to human triage"
        ),
    )
    print(json.dumps({
        "mapped": len(result.mapped),
        "triage": len(result.triage),
        "policy_id": resp["policy"]["policy_id"],
        "version": resp["policy"]["version"],
        "auto_approved": resp.get("auto_approved", False),
        "guards": [{"id": g["id"], "scenario": g["scenario"],
                     "on_fail": g["on_fail"], "threshold": g["threshold"]}
                    for g in result.compiled_document["spec"]["guards"]],
    }, indent=2))
    return 0


def _cmd_scheduler(args: argparse.Namespace) -> int:
    run_scheduler(Path(args.config))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser("guardx_automation")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("feed-gitleaks")
    f.add_argument("--tenant", required=True)
    f.add_argument("--policy", required=True)
    f.add_argument("--source", required=True, help="Path or URL to Gitleaks JSON")

    a = sub.add_parser("autotune")
    a.add_argument("--tenant", required=True)
    a.add_argument("--app", required=True)
    a.add_argument("--policy", required=True)
    a.add_argument("--days-lookback", type=int, default=14)
    a.add_argument("--min-labeled", type=int, default=20)

    s = sub.add_parser("synthesize")
    s.add_argument("--tenant", required=True)
    s.add_argument("--policy", required=True)
    s.add_argument("--apps", required=True, help="comma-separated app slugs")
    s.add_argument("--envs", default="prod", help="comma-separated environments")
    s.add_argument("--input", required=True, help="Path to PDF or text policy doc")

    sc = sub.add_parser("scheduler")
    sc.add_argument("--config", required=True)

    args = p.parse_args(argv)
    if args.cmd == "feed-gitleaks":
        return _cmd_feed(args)
    if args.cmd == "autotune":
        return _cmd_autotune(args)
    if args.cmd == "synthesize":
        return _cmd_synthesize(args)
    if args.cmd == "scheduler":
        return _cmd_scheduler(args)
    p.error(f"unknown command: {args.cmd}")


if __name__ == "__main__":
    sys.exit(main())
