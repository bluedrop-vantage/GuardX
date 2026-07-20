"""Rubric loader.

Rubrics are versioned data files. A rubric spec looks like `id@version` and
resolves to `<rubrics_dir>/<id>@<version>.yaml`. The default rubric dir is
the sibling `rubrics/` directory; override with GUARDX_RUBRICS_DIR.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Rubric:
    id: str
    version: str
    scenario: str
    system: str
    user_template: str
    model: dict[str, Any]
    extras: dict[str, Any]  # anything not in the covered fields (e.g. categories)


def _rubrics_dir() -> Path:
    override = os.environ.get("GUARDX_RUBRICS_DIR")
    if override:
        return Path(override)
    # detectors/llm_judge/llm_judge/rubric.py → sibling `rubrics/`
    return Path(__file__).resolve().parents[1] / "rubrics"


@lru_cache(maxsize=64)
def load_rubric(spec: str, rubrics_dir: str | None = None) -> Rubric:
    """Load `id@version` from disk. Cached — rubrics are immutable data."""
    if "@" not in spec:
        raise ValueError(f"rubric spec must be 'id@version', got {spec!r}")
    base = Path(rubrics_dir) if rubrics_dir else _rubrics_dir()
    path = base / f"{spec}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"rubric not found: {path}")
    doc = yaml.safe_load(path.read_text())
    return Rubric(
        id=doc["id"],
        version=str(doc["version"]),
        scenario=doc["scenario"],
        system=doc.get("system", ""),
        user_template=doc.get("user", ""),
        model=dict(doc.get("model") or {}),
        extras={k: v for k, v in doc.items() if k not in {"id", "version", "scenario", "system", "user", "model"}},
    )
