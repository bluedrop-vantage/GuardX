"""OIDC JWT verification with JWKS caching.

Provider-agnostic — works against any OIDC provider that exposes a JWKS
endpoint (Supabase Auth, Keycloak, Auth0, Okta, Google, Dex, etc.). The Control
API doesn't do the login flow itself; it verifies bearer tokens minted by the
IdP that the console (or any client) already authenticated with.

Design:
  * JWKS is fetched lazily and cached for `ttl_seconds` (default 15 min).
  * `kid` in the JWT header selects the verifying key; on cache miss we
    refresh once (so key rotation works without a restart).
  * The role claim is looked up via a **dotted path** so any IdP that
    embeds custom claims under `app_metadata`, `user_metadata`,
    `resource_access.<client>.roles`, etc. is one config line away.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx
import jwt
from jwt import PyJWKClient


class OIDCError(Exception):
    """Raised for verification failures. The exception message is safe to
    surface — do not leak claim contents."""


@dataclass(frozen=True)
class OIDCConfig:
    """Runtime config for OIDC bearer-token verification."""
    enabled: bool
    issuer: str                    # expected `iss` claim
    audience: Optional[str]        # expected `aud` claim; None → skip check
    jwks_url: str                  # where to fetch verifying keys
    role_claim: str                # dotted path, e.g. "app_metadata.guardx_role"
    subject_claim: str             # dotted path, e.g. "sub" or "email"
    leeway_seconds: int = 30       # clock-skew allowance
    ttl_seconds: int = 900         # JWKS cache TTL

    @property
    def issuer_ok(self) -> bool:
        return bool(self.issuer.strip())


class JWKSCache:
    """Thread-safe JWKS cache with a refresh-on-TTL-expiry policy.

    Lazy: the PyJWKClient (which fetches the JWKS on first use) is not
    constructed until `get_signing_key` is called. This lets a disabled
    OIDC config coexist with an empty/placeholder JWKS URL.
    """

    def __init__(self, jwks_url: str, ttl_seconds: int = 900):
        self._url = jwks_url
        self._ttl = ttl_seconds
        self._client: PyJWKClient | None = None
        self._lock = threading.Lock()
        self._loaded_at = 0.0

    def get_signing_key(self, token: str):
        with self._lock:
            expired = self._client is None or (time.monotonic() - self._loaded_at) > self._ttl
            if expired:
                self._client = PyJWKClient(self._url, cache_keys=True, lifespan=self._ttl)
                self._loaded_at = time.monotonic()
            client = self._client
        return client.get_signing_key_from_jwt(token)


# --- Dotted-path claim lookup ------------------------------------------------

def resolve_claim(claims: dict[str, Any], path: str) -> Any:
    """Look up a nested claim by dotted path.

    Supports plain dict traversal + numeric list indices. Returns None on any
    miss — callers must handle "role claim absent" explicitly (usually by
    rejecting the token with a clear message).
    """
    cur: Any = claims
    for segment in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(segment)
        elif isinstance(cur, list):
            try:
                cur = cur[int(segment)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


# --- Verification -----------------------------------------------------------

class OIDCVerifier:
    """Verifies bearer JWTs against a configured OIDC provider."""

    def __init__(self, config: OIDCConfig, cache: Optional[JWKSCache] = None):
        self.cfg = config
        self._cache = cache or JWKSCache(config.jwks_url, config.ttl_seconds)

    def verify(self, token: str) -> dict[str, Any]:
        """Return decoded claims on success. Raises OIDCError on any failure."""
        if not self.cfg.enabled:
            raise OIDCError("OIDC disabled")
        try:
            key = self._cache.get_signing_key(token)
        except (jwt.exceptions.PyJWKClientError, httpx.HTTPError) as e:
            raise OIDCError(f"JWKS: {e}") from e

        options: dict[str, Any] = {
            "verify_aud": self.cfg.audience is not None,
            "verify_iss": bool(self.cfg.issuer_ok),
            "require": ["exp", "iat", "iss"],
        }
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[key.algorithm_name] if key.algorithm_name else ["RS256", "ES256", "HS256"],
                issuer=self.cfg.issuer if self.cfg.issuer_ok else None,
                audience=self.cfg.audience if self.cfg.audience else None,
                options=options,
                leeway=self.cfg.leeway_seconds,
            )
        except jwt.InvalidTokenError as e:
            raise OIDCError(f"invalid token: {e}") from e

        return claims
