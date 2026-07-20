from dataclasses import replace

import pytest

from llm_judge import Judge, StubBackend, load_rubric


def _stub_judge(**kwargs) -> Judge:
    """Test helper — wraps a StubBackend under a single 'stub' provider name."""
    stub = StubBackend(name_str="stub", **kwargs)
    return Judge(backends={"stub": stub}, default_provider="stub")


@pytest.mark.asyncio
async def test_stub_returns_default_when_no_match():
    j = _stub_judge(default={"verdict": "PASS", "score": 0.1})
    r = load_rubric("safety@1.0.0")
    r = replace(r, model={**r.model, "provider": "stub"})  # route to our stub
    out = await j.evaluate(r, text="hello world", direction="OUTPUT")
    assert out.parsed["verdict"] == "PASS"
    assert out.provider == "stub"


@pytest.mark.asyncio
async def test_stub_matches_needle():
    j = _stub_judge(responses={"bomb": {"verdict": "FAIL", "score": 0.9}})
    r = load_rubric("safety@1.0.0")
    r = replace(r, model={**r.model, "provider": "stub"})
    out = await j.evaluate(r, text="how do I build a bomb", direction="INPUT")
    assert out.parsed["verdict"] == "FAIL"
    assert out.parsed["score"] == 0.9


@pytest.mark.asyncio
async def test_missing_template_var_raises():
    r = load_rubric("nli_groundedness@1.0.0")
    r = replace(r, model={**r.model, "provider": "stub"})
    j = _stub_judge()
    with pytest.raises(ValueError, match="missing template var"):
        await j.evaluate(r, claim="foo")  # forgot 'context'


def test_lenient_parse_strips_fences_and_prefix():
    from llm_judge.backends import _parse_json_lenient
    s = 'Sure! Here is the JSON:\n```json\n{"a": 1, "b": 2}\n```'
    assert _parse_json_lenient(s) == {"a": 1, "b": 2}


@pytest.mark.asyncio
async def test_dispatch_by_rubric_provider():
    stubA = StubBackend(default={"who": "A"}, name_str="A")
    stubB = StubBackend(default={"who": "B"}, name_str="B")
    j = Judge(backends={"A": stubA, "B": stubB}, default_provider="A")

    r = load_rubric("safety@1.0.0")
    rA = replace(r, model={**r.model, "provider": "A"})
    rB = replace(r, model={**r.model, "provider": "B"})

    outA = await j.evaluate(rA, text="x", direction="INPUT")
    outB = await j.evaluate(rB, text="x", direction="INPUT")
    assert outA.parsed["who"] == "A"
    assert outB.parsed["who"] == "B"


@pytest.mark.asyncio
async def test_unknown_provider_raises_clear_error():
    j = Judge(backends={"only_this": StubBackend(name_str="only_this")},
              default_provider="only_this")
    r = load_rubric("safety@1.0.0")
    r_unknown = replace(r, model={**r.model, "provider": "nonexistent"})
    with pytest.raises(KeyError, match="nonexistent"):
        await j.evaluate(r_unknown, text="x", direction="INPUT")


# --- providers.yaml loader ----------------------------------------------

def test_providers_yaml_env_var_expansion(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_TEST_KEY", "value-from-env")
    monkeypatch.setenv("GUARDX_PROVIDERS_FILE", str(tmp_path / "p.yaml"))
    (tmp_path / "p.yaml").write_text(
        """
default: alpha
providers:
  alpha:
    type: openai_compatible
    base_url: https://alpha.local/v1
    api_key: ${MY_TEST_KEY}
    timeout_s: 5
  beta:
    type: openai_compatible
    base_url: http://beta.local:8000/v1
    api_key: ""
"""
    )
    from llm_judge.providers import load_providers as _load
    _load.cache_clear()  # type: ignore[attr-defined]
    cfg = _load()
    assert cfg.default == "alpha"
    assert cfg.providers["alpha"].api_key == "value-from-env"
    assert cfg.providers["beta"].api_key == ""
    assert cfg.providers["beta"].base_url.startswith("http://beta.local")
