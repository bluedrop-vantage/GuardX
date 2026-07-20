"""Provider registry — loads config/providers.yaml, expands env vars, and
constructs the right backend per provider name.

Rubrics only need to name a provider (`model.provider: deepinfra`). The user
edits `config/providers.yaml` to point that name at a local vLLM, a hosted
API, or anything OpenAI-compatible. No detector code changes when swapping.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


_ENV_REF = re.compile(r"\$\{([A-Z0-9_]+)\}")


@dataclass
class ProviderConfig:
    name: str
    type: str
    base_url: str
    api_key: str = ""
    timeout_s: float = 15.0
    default_model: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvidersConfig:
    default: str
    providers: dict[str, ProviderConfig]

    def get(self, name: str | None) -> ProviderConfig:
        name = name or self.default
        try:
            return self.providers[name]
        except KeyError:
            raise KeyError(
                f"provider {name!r} not configured; available: {sorted(self.providers)}"
            )


def _expand(v: Any) -> Any:
    if isinstance(v, str):
        def _replace(m: re.Match) -> str:
            var = m.group(1)
            # Tolerate the .env quoted form (`KEY='value'` → strip surrounding
            # single/double quotes when reading the env).
            raw = os.environ.get(var, "")
            return raw.strip("'\"")
        return _ENV_REF.sub(_replace, v)
    return v


def _default_config_path() -> Path:
    """Repo-root config/providers.yaml unless GUARDX_PROVIDERS_FILE overrides."""
    override = os.environ.get("GUARDX_PROVIDERS_FILE")
    if override:
        return Path(override)
    # detectors/llm_judge/llm_judge/providers.py → repo root is 3 levels up.
    return Path(__file__).resolve().parents[3] / "config" / "providers.yaml"


@lru_cache(maxsize=4)
def load_providers(path: str | None = None) -> ProvidersConfig:
    """Load providers config once per process. Env-var interpolation is
    applied at load time — bumping a key requires a restart.

    A missing file returns an empty registry with a null default; detectors
    then fail fast with a clear message when a rubric references a provider.
    """
    p = Path(path) if path else _default_config_path()
    if not p.exists():
        return ProvidersConfig(default="", providers={})

    doc = yaml.safe_load(p.read_text()) or {}
    provs: dict[str, ProviderConfig] = {}
    for name, raw in (doc.get("providers") or {}).items():
        provs[name] = ProviderConfig(
            name=name,
            type=str(raw.get("type", "openai_compatible")),
            base_url=str(_expand(raw.get("base_url", ""))),
            api_key=str(_expand(raw.get("api_key", ""))),
            timeout_s=float(raw.get("timeout_s", 15.0)),
            default_model=raw.get("default_model"),
            extra={k: v for k, v in raw.items() if k not in {
                "type", "base_url", "api_key", "timeout_s", "default_model",
            }},
        )
    return ProvidersConfig(default=str(doc.get("default", "")), providers=provs)
