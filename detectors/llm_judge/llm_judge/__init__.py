"""GuardX LLM judge shim.

Backends supported today:
  - together   Together.ai OpenAI-compatible chat API
  - openai     OpenAI or compatible endpoints (base_url override)
  - stub       Deterministic fake — used in unit tests, no network

Rubrics are versioned YAML data (see ../rubrics/). A single Judge instance can
serve many rubrics; picking one is a per-call choice.
"""

__version__ = "0.1.0"

from .backends import (
    Judge,
    JudgeBackend,
    JudgeResult,
    OpenAICompatBackend,
    StubBackend,
    TogetherBackend,
)
from .providers import ProviderConfig, ProvidersConfig, load_providers
from .rubric import Rubric, load_rubric

__all__ = [
    "Judge",
    "JudgeBackend",
    "JudgeResult",
    "OpenAICompatBackend",
    "StubBackend",
    "TogetherBackend",
    "ProviderConfig",
    "ProvidersConfig",
    "load_providers",
    "Rubric",
    "load_rubric",
]
