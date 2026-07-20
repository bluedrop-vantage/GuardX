"""Entity pack loader + compiled recognizer registry."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable

import regex  # third-party: supports lookarounds required by our patterns.
import yaml


@dataclass
class Entity:
    label: str
    pattern: "regex.Pattern[str]"
    context_words: list[str] = field(default_factory=list)
    base_confidence: float = 0.5
    validators: list[str] = field(default_factory=list)
    requires_context: bool = False


@dataclass
class EntityPack:
    pack_id: str
    version: str
    entities: list[Entity]


def _compile_entity(raw: dict) -> Entity:
    return Entity(
        label=raw["label"],
        pattern=regex.compile(raw["regex"]),
        context_words=[w.lower() for w in raw.get("context_words", [])],
        base_confidence=float(raw.get("base_confidence", 0.5)),
        validators=list(raw.get("validators", [])),
        requires_context=bool(raw.get("requires_context", False)),
    )


def _packs_dir() -> Path:
    """Default entity-pack directory.

    Container: /entity_packs (set by GUARDX_ENTITY_PACKS_DIR).
    Dev tree:  repo-root/entity_packs.
    """
    override = os.environ.get("GUARDX_ENTITY_PACKS_DIR")
    if override:
        return Path(override)
    # detectors/pii/pii_detector/entity_pack.py → repo root is 3 parents up.
    return Path(__file__).resolve().parents[3] / "entity_packs"


@lru_cache(maxsize=32)
def load_pack(spec: str, packs_dir: str | None = None) -> EntityPack:
    """Load an entity pack by spec 'pack-id@version'.

    Looks for '<packs_dir>/<pack-id>@<version>.yaml'.
    """
    root = Path(packs_dir) if packs_dir else _packs_dir()
    path = root / f"{spec}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"entity pack not found: {path}")
    data = yaml.safe_load(path.read_text())
    entities = [_compile_entity(e) for e in data.get("entities", [])]
    return EntityPack(
        pack_id=data["id"],
        version=str(data.get("version", "0.0.0")),
        entities=entities,
    )
