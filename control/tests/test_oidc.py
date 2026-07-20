"""OIDC verifier tests.

Signs JWTs with an in-test RSA keypair and points the verifier at a JWKS
returned by a monkeypatched httpx response, so no network is needed.
"""
from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from guardx_control.api.auth import (
    Role,
    _map_role,
    _principal_from_bearer,
    reset_verifier_cache,
)
from guardx_control.api.oidc import OIDCConfig, OIDCError, OIDCVerifier, resolve_claim


# --- Test fixtures ---------------------------------------------------------

def _int_to_b64url(n: int) -> str:
    """Encode a big int as base64url for a JWK."""
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture
def rsa_kid() -> str:
    return "test-key-1"


@pytest.fixture
def rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def jwks_payload(rsa_keypair, rsa_kid):
    pub = rsa_keypair.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": rsa_kid,
                "use": "sig",
                "alg": "RS256",
                "n": _int_to_b64url(pub.n),
                "e": _int_to_b64url(pub.e),
            }
        ]
    }


@pytest.fixture
def mk_token(rsa_keypair, rsa_kid):
    """Factory that mints a JWT signed with the fixture keypair."""
    def _mk(**overrides):
        now = int(time.time())
        payload = {
            "iss": "https://idp.example.com",
            "aud": "guardx-console",
            "sub": "user-abc",
            "iat": now,
            "exp": now + 300,
            "email": "author@acme.com",
            "app_metadata": {"guardx_role": "approver"},
        }
        payload.update(overrides)
        return jwt.encode(
            payload,
            key=rsa_keypair,
            algorithm="RS256",
            headers={"kid": rsa_kid},
        )
    return _mk


class _StubCache:
    """Test double for JWKSCache — resolves kid → PyJWK from a static payload."""
    def __init__(self, payload):
        self._payload = payload

    def get_signing_key(self, token):
        hdr = jwt.get_unverified_header(token)
        for k in self._payload["keys"]:
            if k["kid"] == hdr.get("kid"):
                from jwt import PyJWK
                return PyJWK(k)
        raise Exception("no matching kid")


def _verifier(cfg: OIDCConfig, jwks_payload) -> OIDCVerifier:
    """Build a verifier whose JWKS fetch is patched to return the fixture."""
    v = OIDCVerifier(cfg)
    v._cache = _StubCache(jwks_payload)  # type: ignore[attr-defined]
    return v


# --- resolve_claim ---------------------------------------------------------

def test_resolve_claim_simple():
    assert resolve_claim({"sub": "abc"}, "sub") == "abc"


def test_resolve_claim_dotted():
    assert resolve_claim(
        {"app_metadata": {"guardx_role": "author"}},
        "app_metadata.guardx_role",
    ) == "author"


def test_resolve_claim_missing_returns_none():
    assert resolve_claim({}, "app_metadata.guardx_role") is None


def test_resolve_claim_wrong_shape_returns_none():
    # Traversing into a scalar mid-path.
    assert resolve_claim({"a": "not-a-dict"}, "a.b.c") is None


# --- _map_role --------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("admin", Role.ADMIN),
    ("Author", Role.AUTHOR),
    ("guardx-approver", Role.APPROVER),
    ("guardx_reviewer", Role.REVIEWER),
    (["viewer"], Role.VIEWER),
    (["guardx-admin", "other"], Role.ADMIN),
    (["not-a-role", "guardx-author"], Role.AUTHOR),
    ("not-a-role", None),
    ([], None),
    (None, None),
    (42, None),
])
def test_map_role(raw, expected):
    assert _map_role(raw) == expected


# --- OIDCVerifier ----------------------------------------------------------

def test_verify_happy_path(mk_token, jwks_payload):
    cfg = OIDCConfig(
        enabled=True,
        issuer="https://idp.example.com",
        audience="guardx-console",
        jwks_url="https://idp.example.com/jwks",
        role_claim="app_metadata.guardx_role",
        subject_claim="sub",
    )
    v = _verifier(cfg, jwks_payload)
    claims = v.verify(mk_token())
    assert claims["sub"] == "user-abc"
    assert resolve_claim(claims, "app_metadata.guardx_role") == "approver"


def test_verify_rejects_expired_token(mk_token, jwks_payload):
    cfg = OIDCConfig(
        enabled=True,
        issuer="https://idp.example.com",
        audience="guardx-console",
        jwks_url="https://idp.example.com/jwks",
        role_claim="app_metadata.guardx_role",
        subject_claim="sub",
    )
    v = _verifier(cfg, jwks_payload)
    now = int(time.time())
    with pytest.raises(OIDCError, match="invalid token"):
        v.verify(mk_token(exp=now - 100, iat=now - 200))


def test_verify_rejects_wrong_issuer(mk_token, jwks_payload):
    cfg = OIDCConfig(
        enabled=True,
        issuer="https://idp.example.com",
        audience="guardx-console",
        jwks_url="https://idp.example.com/jwks",
        role_claim="app_metadata.guardx_role",
        subject_claim="sub",
    )
    v = _verifier(cfg, jwks_payload)
    with pytest.raises(OIDCError, match="invalid token"):
        v.verify(mk_token(iss="https://attacker.example.com"))


def test_verify_rejects_wrong_audience(mk_token, jwks_payload):
    cfg = OIDCConfig(
        enabled=True,
        issuer="https://idp.example.com",
        audience="guardx-console",
        jwks_url="https://idp.example.com/jwks",
        role_claim="app_metadata.guardx_role",
        subject_claim="sub",
    )
    v = _verifier(cfg, jwks_payload)
    with pytest.raises(OIDCError, match="invalid token"):
        v.verify(mk_token(aud="other-app"))


def test_verify_skips_audience_when_not_configured(mk_token, jwks_payload):
    cfg = OIDCConfig(
        enabled=True,
        issuer="https://idp.example.com",
        audience=None,   # skip aud check
        jwks_url="https://idp.example.com/jwks",
        role_claim="app_metadata.guardx_role",
        subject_claim="sub",
    )
    v = _verifier(cfg, jwks_payload)
    claims = v.verify(mk_token(aud="anything"))
    assert claims["sub"] == "user-abc"


def test_verify_disabled_raises():
    cfg = OIDCConfig(
        enabled=False, issuer="", audience=None,
        jwks_url="", role_claim="", subject_claim="",
    )
    v = OIDCVerifier(cfg)
    with pytest.raises(OIDCError, match="disabled"):
        v.verify("anything")


# --- End-to-end via _principal_from_bearer (exercises the FastAPI wiring) --

def test_principal_from_bearer_returns_authorized_principal(
    monkeypatch, mk_token, jwks_payload, rsa_keypair, rsa_kid
):
    from guardx_control.config import get_settings

    monkeypatch.setenv("GUARDX_OIDC_ENABLED", "true")
    monkeypatch.setenv("GUARDX_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("GUARDX_OIDC_AUDIENCE", "guardx-console")
    monkeypatch.setenv("GUARDX_OIDC_JWKS_URL", "https://idp.example.com/jwks")
    monkeypatch.setenv("GUARDX_OIDC_ROLE_CLAIM", "app_metadata.guardx_role")
    monkeypatch.setenv("GUARDX_OIDC_SUBJECT_CLAIM", "sub")
    get_settings.cache_clear()  # type: ignore[attr-defined]
    reset_verifier_cache()

    # Patch the JWKS cache inside the singleton verifier.
    from guardx_control.api.auth import _verifier as _get_verifier
    v = _get_verifier()
    assert v is not None
    v._cache = _StubCache(jwks_payload)  # type: ignore[attr-defined]

    token = mk_token()
    p = _principal_from_bearer(token)
    assert p.subject == "user-abc"
    assert p.role == Role.APPROVER


def test_principal_from_bearer_missing_role_claim_raises_403(
    monkeypatch, mk_token, jwks_payload
):
    from fastapi import HTTPException
    from guardx_control.config import get_settings

    monkeypatch.setenv("GUARDX_OIDC_ENABLED", "true")
    monkeypatch.setenv("GUARDX_OIDC_ISSUER", "https://idp.example.com")
    monkeypatch.setenv("GUARDX_OIDC_AUDIENCE", "guardx-console")
    monkeypatch.setenv("GUARDX_OIDC_JWKS_URL", "https://idp.example.com/jwks")
    monkeypatch.setenv("GUARDX_OIDC_ROLE_CLAIM", "app_metadata.guardx_role")
    monkeypatch.setenv("GUARDX_OIDC_SUBJECT_CLAIM", "sub")
    get_settings.cache_clear()  # type: ignore[attr-defined]
    reset_verifier_cache()

    from guardx_control.api.auth import _verifier as _get_verifier
    v = _get_verifier()
    assert v is not None
    v._cache = _StubCache(jwks_payload)  # type: ignore[attr-defined]

    # Token with app_metadata missing → 403 with a clear message.
    token = mk_token(app_metadata={})
    with pytest.raises(HTTPException) as excinfo:
        _principal_from_bearer(token)
    assert excinfo.value.status_code == 403
    assert "guardx_role" in str(excinfo.value.detail)
