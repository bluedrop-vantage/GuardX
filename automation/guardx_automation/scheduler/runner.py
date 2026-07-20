"""APScheduler-based long-running runner for feed + autotuner tasks.

Per the plan's solo-builder note: Temporal is deferred to when the synthesizer's
multi-step durable workflow lands. For cron-shaped, idempotent jobs
(feed ingestor + nightly autotuner) APScheduler is plenty.

Config file (YAML) shape:

    tasks:
      - name: gitleaks-acme-hourly
        kind: gitleaks_feed
        cron: "0 * * * *"      # every hour
        args:
          tenant: acme
          policy_id: pii-financial-services
          source: /var/lib/guardx/rulesets/gitleaks.json

      - name: autotune-acme-nightly
        kind: autotuner
        cron: "17 3 * * *"     # 03:17 UTC daily
        args:
          tenant: acme
          app: claims-bot
          policy_id: pii-financial-services
          days_lookback: 14
"""
from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from ..client import ControlClient
from ..autotuner import run_autotuner
from ..feeds import run_gitleaks_ingestor


log = logging.getLogger("guardx.automation")


@dataclass
class TaskSpec:
    name: str
    kind: str                        # "gitleaks_feed" | "autotuner"
    cron: str                        # 5-field cron
    args: dict[str, Any]


# --- task adapters -------------------------------------------------------

def _run_gitleaks(args: dict[str, Any], client: ControlClient) -> None:
    log.info("gitleaks feed start: tenant=%s policy=%s source=%s",
              args.get("tenant"), args.get("policy_id"), args.get("source"))
    out = run_gitleaks_ingestor(
        tenant=args["tenant"],
        policy_id=args["policy_id"],
        source=args["source"],
        client=client,
    )
    log.info("gitleaks feed done: submitted=%s added=%s reason=%s",
              out.submitted, out.added_rule_ids, out.reason)


def _run_autotuner(args: dict[str, Any], client: ControlClient) -> None:
    log.info("autotuner start: tenant=%s app=%s policy=%s",
              args.get("tenant"), args.get("app"), args.get("policy_id"))
    out = run_autotuner(
        tenant=args["tenant"],
        app=args["app"],
        policy_id=args["policy_id"],
        days_lookback=int(args.get("days_lookback", 14)),
        client=client,
    )
    log.info("autotuner done: proposal=%s recommendations=%d",
              out.proposal_submitted, len(out.recommendations))


_KINDS = {
    "gitleaks_feed": _run_gitleaks,
    "autotuner": _run_autotuner,
}


# --- runner -------------------------------------------------------------

def load_tasks(config_path: Path) -> list[TaskSpec]:
    doc = yaml.safe_load(config_path.read_text())
    tasks_raw = (doc or {}).get("tasks") or []
    tasks: list[TaskSpec] = []
    for t in tasks_raw:
        if t.get("kind") not in _KINDS:
            raise ValueError(f"unknown kind: {t.get('kind')!r}")
        tasks.append(TaskSpec(
            name=t["name"], kind=t["kind"],
            cron=t.get("cron", "0 * * * *"),
            args=t.get("args") or {},
        ))
    return tasks


def run_scheduler(config_path: Path, control: ControlClient | None = None) -> None:
    logging.basicConfig(level=logging.INFO,
                         format="%(asctime)s %(levelname)s %(name)s %(message)s")
    control = control or ControlClient()
    tasks = load_tasks(config_path)
    sched = BlockingScheduler(timezone="UTC")

    for t in tasks:
        adapter = _KINDS[t.kind]
        trigger = CronTrigger.from_crontab(t.cron, timezone="UTC")
        sched.add_job(
            adapter, trigger=trigger, id=t.name, name=t.name,
            args=[t.args, control], misfire_grace_time=300,
            coalesce=True, max_instances=1,
        )
        log.info("scheduled %s (%s) — cron=%r", t.name, t.kind, t.cron)

    stop = {"signalled": False}
    def _handle(_sig, _frame):
        stop["signalled"] = True
        sched.shutdown(wait=False)
    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    while not stop["signalled"]:
        time.sleep(0.5)
