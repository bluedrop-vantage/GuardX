"""Auth: OIDC bearer for humans, X-GuardX-Key for service tokens.

Both paths converge on a single `Principal(subject, role)` — every route
downstream (RBAC via `require_role`, SoD via `created_by != subject`) works
regardless of which path minted it.

Selection:
  * `Authorization: Bearer <jwt>`   → OIDC path (needs oidc_enabled=True)
  * `X-GuardX-Key: <key>`           → API-key path (service tokens / dev)

If both are set, Bearer wins so a user's token isn't shadowed by a service
key that happens to be lying in the environment.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Optional

from fastapi import Depends, Header, HTTPException, status

from ..config import get_settings
from .oidc import OIDCConfig, OIDCError, OIDCVerifier, resolve_claim


class Role(str, Enum):
    VIEWER = "viewer"
    AUTHOR = "author"
    REVIEWER = "reviewer"
    APPROVER = "approver"
    ADMIN = "admin"
    SERVICE = "service"      # automation-plane service tokens


@dataclass(frozen=True)
class Principal:
    subject: str
    role: Role


_ROLE_RANK = {
    Role.VIEWER: 0,
    Role.AUTHOR: 1,
    Role.REVIEWER: 2,
    Role.APPROVER: 3,
    Role.ADMIN: 4,
    Role.SERVICE: 1,
}


# --- OIDC verifier singleton -----------------------------------------------

@lru_cache(maxsize=1)
def _verifier() -> Optional[OIDCVerifier]:
    s = get_settings()
    if not s.oidc_enabled or not s.oidc_jwks_url:
        return None
    return OIDCVerifier(OIDCConfig(
        enabled=True,
        issuer=s.oidc_issuer,
        audience=s.oidc_audience or None,
        jwks_url=s.oidc_jwks_url,
        role_claim=s.oidc_role_claim,
        subject_claim=s.oidc_subject_claim,
        leeway_seconds=s.oidc_leeway_seconds,
        ttl_seconds=s.oidc_jwks_ttl_seconds,
    ))


def reset_verifier_cache() -> None:
    """Test helper — bounce the verifier when Settings change."""
    _verifier.cache_clear()


# --- Role mapping ---------------------------------------------------------

def _map_role(raw: object) -> Optional[Role]:
    """Map an IdP-issued role claim to a Role.

    Accepts a bare string ("admin") or a list containing one ("guardx-approver"
    from a Keycloak `groups` claim). Also accepts the "guardx-<role>" prefixed
    form so a single IdP can host multiple apps.
    """
    def _norm(s: str) -> str:
        s = s.strip().lower()
        return s.removeprefix("guardx-").removeprefix("guardx_")

    candidates: list[str] = []
    if isinstance(raw, str):
        candidates.append(raw)
    elif isinstance(raw, list):
        for x in raw:
            if isinstance(x, str):
                candidates.append(x)
    for c in candidates:
        try:
            return Role(_norm(c))
        except ValueError:
            continue
    return None


# --- Principal builders ---------------------------------------------------

def _principal_from_key(key: str) -> Principal:
    settings = get_settings()
    if key == settings.api_key_admin:
        return Principal(subject="admin@dev", role=Role.ADMIN)
    if key == settings.api_key_service:
        return Principal(subject="svc@automation", role=Role.SERVICE)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid api key")


def _principal_from_bearer(token: str) -> Principal:
    verifier = _verifier()
    if verifier is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC not configured; Bearer tokens rejected",
        )
    try:
        claims = verifier.verify(token)
    except OIDCError as e:
        # Include the reason (safe: we control the strings) so ops can debug.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail=f"invalid bearer token: {e}") from e

    settings = get_settings()
    subject = resolve_claim(claims, settings.oidc_subject_claim)
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail=f"subject claim {settings.oidc_subject_claim!r} missing")

    role_raw = resolve_claim(claims, settings.oidc_role_claim)
    role = _map_role(role_raw)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"role claim {settings.oidc_role_claim!r} missing/invalid — "
                "IdP must set a guardx_role value (viewer|author|reviewer|approver|admin)"
            ),
        )
    return Principal(subject=subject, role=role)


# --- Dependency (public) --------------------------------------------------

def current_principal(
    authorization: str | None = Header(default=None),
    x_guardx_key: str | None = Header(default=None),
) -> Principal:
    # Bearer wins over API key — a user's token takes precedence over any
    # service key that happens to be set in the caller's environment.
    if authorization:
        parts = authorization.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return _principal_from_bearer(parts[1].strip())
    if x_guardx_key:
        return _principal_from_key(x_guardx_key)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing credentials (send Authorization: Bearer <jwt> or X-GuardX-Key)",
    )


def require_role(*allowed: Role):
    def _dep(p: Principal = Depends(current_principal)) -> Principal:
        if p.role not in allowed and p.role is not Role.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"role {p.role.value} not authorized; need one of {[r.value for r in allowed]}",
            )
        return p
    return _dep
