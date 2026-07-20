"""Judge backends.

A single `OpenAICompatBackend` covers every provider whose API implements the
OpenAI chat-completions shape: Together, DeepInfra, OpenAI, Groq, Fireworks,
xAI, Ollama, vLLM, LM Studio, TGI. Adding a non-compatible provider (native
Anthropic / Google) means a new Backend class implementing the same protocol.

Backends are constructed by `Judge.from_providers(...)` — callers get one
`Judge` that dispatches to the right backend based on `rubric.model.provider`.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from .providers import ProviderConfig, ProvidersConfig, load_providers
from .rubric import Rubric


# --- shared result shape -------------------------------------------------

@dataclass
class JudgeCall:
    rubric: Rubric
    system: str
    user: str


@dataclass
class JudgeResult:
    raw: str                                # verbatim reply — for evidence + parsers
    parsed: dict[str, Any] | None           # populated when response_format=json_object
    latency_ms: int
    model: str
    provider: str
    tokens_prompt: int = 0
    tokens_completion: int = 0


class JudgeBackend(Protocol):
    def name(self) -> str: ...
    async def complete(self, call: JudgeCall) -> JudgeResult: ...


# --- OpenAI-compatible chat completions backend --------------------------

class OpenAICompatBackend:
    """Serves any endpoint that speaks the OpenAI /chat/completions shape.

    Provider config carries endpoint + auth; rubric carries model + decoding.
    `response_format: json_object` is honored when the rubric asks for it;
    anything else (e.g. `llamaguard`) is left raw for the caller to parse.
    """

    def __init__(self, cfg: ProviderConfig, client: httpx.AsyncClient | None = None):
        self.cfg = cfg
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_s)

    def name(self) -> str:
        return self.cfg.name

    async def complete(self, call: JudgeCall) -> JudgeResult:
        model = call.rubric.model.get("name") or self.cfg.default_model
        if not model:
            raise ValueError(
                f"rubric {call.rubric.id}@{call.rubric.version} has no model.name "
                f"and provider {self.cfg.name!r} has no default_model configured"
            )
        temp = float(call.rubric.model.get("temperature", 0.0))
        max_tokens = int(call.rubric.model.get("max_tokens", 512))
        # response_format is read from either model.response_format or top-level.
        response_format = (
            str(call.rubric.model.get("response_format", "")).lower()
            or str(call.rubric.extras.get("response_format", "json_object")).lower()
        )

        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": call.system},
                {"role": "user", "content": call.user},
            ],
            "temperature": temp,
            "max_tokens": max_tokens,
        }
        # Only send response_format=json_object when the rubric expects JSON.
        # Sending it to Llama-Guard breaks the model's response shape.
        if response_format == "json_object":
            body["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        if self.cfg.api_key:
            headers["Authorization"] = f"Bearer {self.cfg.api_key}"

        t0 = time.perf_counter_ns()
        resp = await self._client.post(
            f"{self.cfg.base_url.rstrip('/')}/chat/completions",
            json=body, headers=headers,
        )
        latency_ms = int((time.perf_counter_ns() - t0) / 1_000_000)
        resp.raise_for_status()
        payload = resp.json()

        content = payload["choices"][0]["message"]["content"]
        parsed: dict[str, Any] | None = None
        if response_format == "json_object":
            try:
                parsed = _parse_json_lenient(content)
            except Exception:  # noqa: BLE001
                parsed = None
        usage = payload.get("usage") or {}
        return JudgeResult(
            raw=content,
            parsed=parsed,
            latency_ms=latency_ms,
            model=model,
            provider=self.cfg.name,
            tokens_prompt=usage.get("prompt_tokens", 0),
            tokens_completion=usage.get("completion_tokens", 0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()


# --- Stub (tests) --------------------------------------------------------

@dataclass
class StubBackend:
    """Deterministic canned responses matched by substring of the user prompt."""
    responses: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw_responses: dict[str, str] = field(default_factory=dict)
    default: dict[str, Any] = field(default_factory=lambda: {"verdict": "PASS", "score": 0.0})
    name_str: str = "stub"

    def name(self) -> str:
        return self.name_str

    async def complete(self, call: JudgeCall) -> JudgeResult:
        # Prefer explicit raw responses (used to fake Llama-Guard-style text).
        for needle, raw in self.raw_responses.items():
            if needle in call.user:
                return JudgeResult(
                    raw=raw, parsed=None, latency_ms=1,
                    model="stub", provider=self.name_str,
                )
        for needle, payload in self.responses.items():
            if needle in call.user:
                return JudgeResult(
                    raw=json.dumps(payload), parsed=payload, latency_ms=1,
                    model="stub", provider=self.name_str,
                )
        return JudgeResult(
            raw=json.dumps(self.default), parsed=self.default, latency_ms=1,
            model="stub", provider=self.name_str,
        )


# --- Judge: multi-provider dispatch --------------------------------------

@dataclass
class Judge:
    """Holds `{provider_name: backend}` and picks per-rubric on evaluate()."""
    backends: dict[str, JudgeBackend]
    default_provider: str = ""

    @classmethod
    def from_providers(cls, cfg: ProvidersConfig | None = None) -> "Judge":
        cfg = cfg or load_providers()
        backends: dict[str, JudgeBackend] = {}
        for name, pcfg in cfg.providers.items():
            if pcfg.type == "openai_compatible":
                backends[name] = OpenAICompatBackend(pcfg)
            # Unknown types are silently skipped — a rubric that later names
            # one gets a clean "not registered" error.
        return cls(backends=backends, default_provider=cfg.default)

    def _pick(self, provider: str | None) -> JudgeBackend:
        name = provider or self.default_provider
        if not name:
            raise ValueError("no provider requested and no default configured")
        try:
            return self.backends[name]
        except KeyError:
            raise KeyError(
                f"provider {name!r} not registered; available: {sorted(self.backends)}"
            )

    async def evaluate(self, rubric: Rubric, **template_vars: str) -> JudgeResult:
        if "{categories}" in rubric.user_template:
            cats = rubric.extras.get("categories") or []
            template_vars.setdefault(
                "categories",
                "\n".join(f"- {c['id']}: {c['label']}" for c in cats),
            )
        try:
            user = rubric.user_template.format(**template_vars)
        except KeyError as e:
            raise ValueError(f"rubric {rubric.id}@{rubric.version} missing template var: {e}")
        backend = self._pick(rubric.model.get("provider"))
        call = JudgeCall(rubric=rubric, system=rubric.system, user=user)
        return await backend.complete(call)


# --- Back-compat helpers -------------------------------------------------

# Retained so existing detector modules and tests still import cleanly.
def build_default_backend() -> JudgeBackend:
    """Return a backend for the default provider from config/providers.yaml.
    New code should use `Judge.from_providers()` directly."""
    cfg = load_providers()
    if not cfg.providers:
        return StubBackend()
    default = cfg.default or next(iter(cfg.providers))
    return OpenAICompatBackend(cfg.providers[default])


class TogetherBackend(OpenAICompatBackend):
    """Deprecated — prefer configuring the `together` provider in
    config/providers.yaml. Kept so existing imports don't break."""
    def __init__(self, api_key: str, base_url: str = "https://api.together.xyz/v1",
                 timeout: float = 12.0):
        super().__init__(ProviderConfig(
            name="together", type="openai_compatible",
            base_url=base_url, api_key=api_key, timeout_s=timeout,
        ))


# --- helpers -------------------------------------------------------------

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _parse_json_lenient(s: str) -> dict[str, Any]:
    """Model output is JSON per the rubric contract; strip fences / prose."""
    s = s.strip()
    m = _FENCE_RE.search(s)
    if m:
        s = m.group(1)
    start = s.find("{")
    end = s.rfind("}")
    if start != -1 and end > start:
        s = s[start : end + 1]
    return json.loads(s)
