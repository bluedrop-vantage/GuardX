"""Policy CRUD + lifecycle.

Enforces invariant I3 (only approval-workflow paths write approved policies)
and separation-of-duty (author cannot approve their own version).
"""
from __future__ import annotations

import base64
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..linter import Severity, lint_policy
from ..models import (
    AuditAction,
    Policy,
    PolicyAudit,
    PolicyOrigin,
    PolicyStatus,
    Tenant,
)
from ..signing import canonical_json, sha256_hex
from .auth import Principal, Role, current_principal, require_role
from .deps import get_db
from .schemas import (
    LintIssueOut,
    PolicyActionRequest,
    PolicyCreate,
    PolicyCreateResult,
    PolicyOut,
    ProposalIn,
    ProposalOut,
)

router = APIRouter(prefix="/v1/policies", tags=["policies"])


def _get_tenant(db: Session, slug: str) -> Tenant:
    t = db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none()
    if not t:
        raise HTTPException(404, f"tenant '{slug}' not found")
    return t


def _to_out(p: Policy, tenant_slug: str) -> PolicyOut:
    return PolicyOut(
        tenant=tenant_slug,
        policy_id=p.policy_id,
        version=p.version,
        status=p.status,
        origin=p.origin,
        created_by=p.created_by,
        created_at=p.created_at.isoformat(),
        approved_by=p.approved_by,
        approved_at=p.approved_at.isoformat() if p.approved_at else None,
        document_hash="sha256:" + p.document_hash.hex(),
        document=p.document,
    )


def _insert_policy(
    db: Session,
    tenant: Tenant,
    document: dict,
    created_by: str,
    origin: PolicyOrigin,
    origin_ref: Optional[dict],
) -> Policy:
    meta = document.get("metadata") or {}
    policy_id = meta.get("id")
    version = meta.get("version")
    if not policy_id or not version:
        raise HTTPException(422, "metadata.id and metadata.version are required")

    # Enforce tenant consistency between path and document.
    if meta.get("tenant") not in (None, tenant.slug):
        raise HTTPException(422, "metadata.tenant does not match tenant scope")
    meta["tenant"] = tenant.slug
    meta["status"] = PolicyStatus.DRAFT.value
    meta["created_by"] = created_by
    meta["origin"] = origin.value
    document["metadata"] = meta

    doc_bytes = canonical_json(document)
    doc_hash = bytes.fromhex(sha256_hex(doc_bytes))

    exists = db.execute(
        select(Policy).where(
            Policy.tenant_id == tenant.id,
            Policy.policy_id == policy_id,
            Policy.version == version,
        )
    ).scalar_one_or_none()
    if exists:
        raise HTTPException(409, f"policy {policy_id}@{version} already exists")

    row = Policy(
        tenant_id=tenant.id,
        policy_id=policy_id,
        version=version,
        status=PolicyStatus.DRAFT.value,
        document=document,
        document_hash=doc_hash,
        origin=origin.value,
        origin_ref=origin_ref,
        created_by=created_by,
    )
    db.add(row)
    db.add(
        PolicyAudit(
            tenant_id=tenant.id,
            policy_id=policy_id,
            version=version,
            action=AuditAction.CREATED.value,
            actor=created_by,
        )
    )
    return row


@router.post("", response_model=PolicyCreateResult, status_code=201)
def create_policy(
    body: PolicyCreate,
    tenant: str = Query(..., description="Tenant slug"),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.AUTHOR, Role.ADMIN)),
) -> PolicyCreateResult:
    issues = lint_policy(body.document)
    if any(i.severity is Severity.ERROR for i in issues):
        raise HTTPException(
            422,
            detail={"lint": [i.as_dict() for i in issues]},
        )
    t = _get_tenant(db, tenant)
    row = _insert_policy(
        db,
        t,
        body.document,
        created_by=principal.subject,
        origin=PolicyOrigin.MANUAL,
        origin_ref=None,
    )
    db.commit()
    db.refresh(row)
    return PolicyCreateResult(
        policy=_to_out(row, t.slug),
        lint=[LintIssueOut(**i.as_dict()) for i in issues],
    )


@router.get("/{policy_id}", response_model=list[PolicyOut])
def list_versions(
    policy_id: str,
    tenant: str = Query(...),
    version: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
) -> list[PolicyOut]:
    t = _get_tenant(db, tenant)
    q = select(Policy).where(Policy.tenant_id == t.id, Policy.policy_id == policy_id)
    if version:
        q = q.where(Policy.version == version)
    q = q.order_by(Policy.created_at.desc())
    rows = db.execute(q).scalars().all()
    if not rows:
        raise HTTPException(404, f"policy {policy_id} not found")
    return [_to_out(r, t.slug) for r in rows]


def _get_policy(db: Session, t: Tenant, policy_id: str, version: str) -> Policy:
    row = db.execute(
        select(Policy).where(
            Policy.tenant_id == t.id,
            Policy.policy_id == policy_id,
            Policy.version == version,
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(404, f"{policy_id}@{version} not found")
    return row


def _audit(db: Session, row: Policy, action: AuditAction, actor: str, note: Optional[str]) -> None:
    db.add(
        PolicyAudit(
            tenant_id=row.tenant_id,
            policy_id=row.policy_id,
            version=row.version,
            action=action.value,
            actor=actor,
            note=note,
        )
    )


@router.post("/{policy_id}/{version}:submit")
def submit_policy(
    policy_id: str,
    version: str,
    body: PolicyActionRequest,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.AUTHOR, Role.ADMIN)),
) -> dict:
    t = _get_tenant(db, tenant)
    row = _get_policy(db, t, policy_id, version)
    if row.status != PolicyStatus.DRAFT.value:
        raise HTTPException(409, f"cannot submit from status={row.status}")
    row.status = PolicyStatus.IN_REVIEW.value
    row.document["metadata"]["status"] = PolicyStatus.IN_REVIEW.value
    _audit(db, row, AuditAction.SUBMITTED, principal.subject, body.note)
    db.commit()
    return {"status": row.status}


@router.post("/{policy_id}/{version}:approve")
def approve_policy(
    policy_id: str,
    version: str,
    body: PolicyActionRequest,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> dict:
    t = _get_tenant(db, tenant)
    row = _get_policy(db, t, policy_id, version)
    if row.status != PolicyStatus.IN_REVIEW.value:
        raise HTTPException(409, f"cannot approve from status={row.status}")

    # Separation of duty (spec §3.3): author cannot approve own version.
    # ADMIN can — a documented emergency path, still stamped in audit.
    if row.created_by == principal.subject and principal.role is not Role.ADMIN:
        raise HTTPException(403, "author cannot approve their own policy version")

    row.status = PolicyStatus.APPROVED.value
    row.approved_by = principal.subject
    from datetime import datetime, timezone
    row.approved_at = datetime.now(timezone.utc)
    row.document["metadata"]["status"] = PolicyStatus.APPROVED.value
    row.document["metadata"]["approved_by"] = principal.subject
    row.document["metadata"]["approved_at"] = row.approved_at.isoformat()
    _audit(db, row, AuditAction.APPROVED, principal.subject, body.note)
    db.commit()
    return {"status": row.status, "approved_by": row.approved_by}


@router.post("/{policy_id}/{version}:reject")
def reject_policy(
    policy_id: str,
    version: str,
    body: PolicyActionRequest,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.REVIEWER, Role.APPROVER, Role.ADMIN)),
) -> dict:
    t = _get_tenant(db, tenant)
    row = _get_policy(db, t, policy_id, version)
    if row.status != PolicyStatus.IN_REVIEW.value:
        raise HTTPException(409, f"cannot reject from status={row.status}")
    row.status = PolicyStatus.DRAFT.value
    row.document["metadata"]["status"] = PolicyStatus.DRAFT.value
    _audit(db, row, AuditAction.REJECTED, principal.subject, body.note)
    db.commit()
    return {"status": row.status}


@router.post("/{policy_id}/{version}:revoke")
def revoke_policy(
    policy_id: str,
    version: str,
    body: PolicyActionRequest,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> dict:
    t = _get_tenant(db, tenant)
    row = _get_policy(db, t, policy_id, version)
    if row.status not in (PolicyStatus.APPROVED.value, PolicyStatus.DEPRECATED.value):
        raise HTTPException(409, f"cannot revoke from status={row.status}")
    row.status = PolicyStatus.REVOKED.value
    row.document["metadata"]["status"] = PolicyStatus.REVOKED.value
    _audit(db, row, AuditAction.REVOKED, principal.subject, body.note)
    db.commit()
    return {"status": row.status}


# ---- Proposals (automation plane; scoped to service principal) ----
proposals_router = APIRouter(prefix="/v1/proposals", tags=["proposals"])


# Auto-approval rules (spec §3.3): only monotonic_add proposals from feeds can
# skip human review. Every auto-approval is stamped in policy_audit with the
# rule id. Anything else stays in `draft` for human intake.
_AUTO_APPROVAL_RULES = {
    ("feed", "monotonic_add"): "AA-1: origin=feed AND change_class=monotonic_add",
}


@proposals_router.post("", response_model=ProposalOut, status_code=201)
def submit_proposal(
    body: ProposalIn,
    tenant: str = Query(...),
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role(Role.SERVICE, Role.ADMIN)),
) -> ProposalOut:
    """Invariant I3: automation writes proposals only.

    Landing status:
      * `feed + monotonic_add`  ⇒ approved (auto-rule AA-1, stamped in audit)
      * anything else           ⇒ draft (human approval required)
    """
    try:
        origin = PolicyOrigin(body.origin)
    except ValueError:
        raise HTTPException(422, f"invalid origin '{body.origin}'")
    if origin is PolicyOrigin.MANUAL:
        raise HTTPException(422, "proposals cannot claim origin=manual")

    issues = lint_policy(body.document)
    if any(i.severity is Severity.ERROR for i in issues):
        raise HTTPException(422, detail={"lint": [i.as_dict() for i in issues]})

    t = _get_tenant(db, tenant)
    row = _insert_policy(
        db,
        t,
        body.document,
        created_by=principal.subject,
        origin=origin,
        origin_ref=body.origin_ref,
    )
    row.change_class = body.change_class

    rule_id = _AUTO_APPROVAL_RULES.get((origin.value, body.change_class or ""))
    if rule_id:
        from datetime import datetime, timezone
        row.status = PolicyStatus.APPROVED.value
        row.approved_by = f"system:{rule_id.split(':', 1)[0]}"
        row.approved_at = datetime.now(timezone.utc)
        row.auto_approval_rule = rule_id
        row.document["metadata"]["status"] = PolicyStatus.APPROVED.value
        row.document["metadata"]["approved_by"] = row.approved_by
        row.document["metadata"]["approved_at"] = row.approved_at.isoformat()
        row.document["metadata"]["auto_approval_rule"] = rule_id
        _audit(db, row, AuditAction.APPROVED, row.approved_by, f"auto-approved: {rule_id}")

    db.commit()
    db.refresh(row)
    return ProposalOut(
        policy=_to_out(row, t.slug),
        lint=[LintIssueOut(**i.as_dict()) for i in issues],
        auto_approved=bool(rule_id),
        auto_approval_rule=rule_id,
    )


# ---- Tenant bootstrap ----
tenants_router = APIRouter(prefix="/v1/tenants", tags=["tenants"])


@tenants_router.post("", status_code=201)
def create_tenant(
    body: dict,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(Role.ADMIN)),
) -> dict:
    slug = body.get("slug")
    if not slug:
        raise HTTPException(422, "slug required")
    existing = db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"tenant '{slug}' already exists")
    t = Tenant(id=uuid.uuid4(), slug=slug)
    db.add(t)
    db.commit()
    return {"id": str(t.id), "slug": t.slug}
