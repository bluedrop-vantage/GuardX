"""Bundle composer + signer.

Given a tenant + environment, collect the current set of approved policies
targeting that environment, compose a manifest, and sign it. Signed bundles
are the only artifact the gateway trusts (spec §3.2 / invariant I1).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Bundle, Detector, Policy, PolicyStatus, Tenant
from ..signing import Ed25519Signer, canonical_json, sha256_hex


def _latest_approved_versions(db: Session, tenant_id: uuid.UUID) -> Iterable[Policy]:
    subq = (
        select(
            Policy.policy_id,
            func.max(Policy.approved_at).label("max_approved_at"),
        )
        .where(
            Policy.tenant_id == tenant_id,
            Policy.status == PolicyStatus.APPROVED.value,
        )
        .group_by(Policy.policy_id)
        .subquery()
    )
    q = (
        select(Policy)
        .join(
            subq,
            (Policy.policy_id == subq.c.policy_id)
            & (Policy.approved_at == subq.c.max_approved_at),
        )
        .where(
            Policy.tenant_id == tenant_id,
            Policy.status == PolicyStatus.APPROVED.value,
        )
    )
    return db.execute(q).scalars().all()


def _detector_refs(db: Session, policies: list[Policy]) -> list[dict]:
    seen: dict[tuple[str, str], dict] = {}
    for p in policies:
        for guard in (p.document.get("spec") or {}).get("guards", []) or []:
            det = guard.get("detector")
            if not det or "@" not in det:
                continue
            did, ver = det.split("@", 1)
            key = (did, ver)
            if key in seen:
                continue
            row = db.get(Detector, key)
            seen[key] = {
                "detector_id": did,
                "version": ver,
                "image_digest": row.image_digest if row else "",
            }
    return sorted(seen.values(), key=lambda r: (r["detector_id"], r["version"]))


def build_bundle(
    db: Session,
    tenant: Tenant,
    environment: str,
    signer: Ed25519Signer,
) -> Bundle:
    settings = get_settings()

    policies = list(_latest_approved_versions(db, tenant.id))
    # Filter to policies scoped to this environment.
    scoped: list[Policy] = []
    for p in policies:
        envs = (p.document.get("spec") or {}).get("applies_to", {}).get("environments", []) or []
        if environment in envs:
            scoped.append(p)

    detectors = _detector_refs(db, scoped)

    next_seq = (
        db.execute(
            select(func.coalesce(func.max(Bundle.bundle_seq), 0)).where(
                Bundle.tenant_id == tenant.id, Bundle.environment == environment
            )
        ).scalar_one()
        or 0
    ) + 1

    manifest = {
        "tenant": tenant.slug,
        "environment": environment,
        "bundle_seq": next_seq,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "max_age_hours": settings.bundle_max_age_hours,
        "policies": [
            {
                "policy_id": p.policy_id,
                "version": p.version,
                "document_hash": "sha256:" + p.document_hash.hex(),
                "document": p.document,
            }
            for p in scoped
        ],
        "detectors": detectors,
    }

    manifest_bytes = canonical_json(manifest)
    manifest_hash = bytes.fromhex(sha256_hex(manifest_bytes))
    signature = signer.sign(manifest_bytes)

    bundle = Bundle(
        tenant_id=tenant.id,
        environment=environment,
        bundle_seq=next_seq,
        manifest=manifest,
        manifest_hash=manifest_hash,
        signature=signature,
        signing_key_id=signer.key_id,
    )
    db.add(bundle)
    return bundle
