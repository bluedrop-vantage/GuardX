"""Bundle build + gateway-facing pull.

`GET /v1/bundles/{env}?since=` is the gateway hot-swap channel. In M0 this is
plain polling (long-poll shell is documented but returns immediately with the
current bundle). Push via Redis is a post-M0 optimization.
"""
from __future__ import annotations

import base64
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..bundle_builder import build_bundle
from ..models import Bundle
from ..signing import Ed25519Signer
from .auth import Principal, Role, current_principal, require_role
from .deps import get_db, get_signer
from .policies import _get_tenant
from .schemas import BundleOut

router = APIRouter(prefix="/v1/bundles", tags=["bundles"])


def _to_out(row: Bundle, tenant_slug: str) -> BundleOut:
    return BundleOut(
        tenant=tenant_slug,
        environment=row.environment,
        bundle_seq=row.bundle_seq,
        manifest=row.manifest,
        manifest_hash="sha256:" + row.manifest_hash.hex(),
        signature_b64=base64.b64encode(row.signature).decode("ascii"),
        signing_key_id=row.signing_key_id,
        created_at=row.created_at.isoformat(),
    )


@router.post("/{environment}:build", response_model=BundleOut, status_code=201)
def build(
    environment: str,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    signer: Ed25519Signer = Depends(get_signer),
    _: Principal = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> BundleOut:
    t = _get_tenant(db, tenant)
    b = build_bundle(db, t, environment, signer)
    db.commit()
    db.refresh(b)
    return _to_out(b, t.slug)


@router.get("/{environment}", response_model=Optional[BundleOut])
def pull(
    environment: str,
    tenant: str = Query(...),
    since: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
) -> Optional[BundleOut]:
    """Gateway pull. 204 when caller is already at the latest seq."""
    t = _get_tenant(db, tenant)
    row = db.execute(
        select(Bundle)
        .where(Bundle.tenant_id == t.id, Bundle.environment == environment)
        .order_by(Bundle.bundle_seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(404, f"no bundle for {tenant}/{environment}")
    if row.bundle_seq <= since:
        response.status_code = 204
        return None
    return _to_out(row, t.slug)


@router.get("/{environment}/signing-key")
def signing_key(
    environment: str,
    signer: Ed25519Signer = Depends(get_signer),
    _: Principal = Depends(current_principal),
) -> dict:
    """Publish the current signing public key so gateways can bootstrap trust.

    Production path: distribute pinned keys out-of-band (config / secret store)
    rather than trust an HTTP fetch. Kept here for dev.
    """
    return {
        "key_id": signer.key_id,
        "algorithm": "Ed25519",
        "public_key_b64": base64.b64encode(signer.public_key_bytes()).decode("ascii"),
    }
