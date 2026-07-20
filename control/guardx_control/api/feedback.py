"""Feedback events — the auto-tuner's raw input (spec §5.3).

Four disposition classes: TP / FP / TN / FN. Sources: user thumbs, analyst,
appeal, autolabel. Feedback rows are append-only (no update/delete API); the
tuner reads a rolling window and fits threshold curves.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import FeedbackEvent
from .auth import Principal, Role, current_principal, require_role
from .deps import get_db

router = APIRouter(prefix="/v1/feedback", tags=["feedback"])


class FeedbackIn(BaseModel):
    tenant: str
    app: str
    event_id: Optional[str] = None
    guard_id: Optional[str] = None
    policy: Optional[str] = None
    source: str = Field(..., description="user_thumbs | analyst | appeal | autolabel")
    disposition: str = Field(..., description="true_positive | false_positive | true_negative | false_negative")
    note: Optional[str] = None


class FeedbackOut(BaseModel):
    id: int
    tenant: str
    app: str
    event_id: Optional[str] = None
    guard_id: Optional[str] = None
    policy: Optional[str] = None
    source: str
    disposition: str
    note: Optional[str] = None
    submitted_by: str
    at: str


def _to_out(row: FeedbackEvent) -> FeedbackOut:
    return FeedbackOut(
        id=row.id, tenant=row.tenant, app=row.app,
        event_id=row.event_id, guard_id=row.guard_id, policy=row.policy,
        source=row.source, disposition=row.disposition, note=row.note,
        submitted_by=row.submitted_by,
        at=row.at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


@router.post("", response_model=FeedbackOut, status_code=201)
def submit_feedback(
    body: FeedbackIn,
    db: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> FeedbackOut:
    row = FeedbackEvent(
        tenant=body.tenant, app=body.app, event_id=body.event_id,
        guard_id=body.guard_id, policy=body.policy,
        source=body.source, disposition=body.disposition,
        note=body.note, submitted_by=principal.subject,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_out(row)


@router.get("", response_model=list[FeedbackOut])
def list_feedback(
    tenant: str = Query(...),
    app: Optional[str] = Query(default=None),
    guard_id: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None, description="ISO ts lower bound"),
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(Role.REVIEWER, Role.APPROVER, Role.SERVICE, Role.ADMIN)),
) -> list[FeedbackOut]:
    q = select(FeedbackEvent).where(FeedbackEvent.tenant == tenant)
    if app:
        q = q.where(FeedbackEvent.app == app)
    if guard_id:
        q = q.where(FeedbackEvent.guard_id == guard_id)
    if since:
        s = since[:-1] + "+00:00" if since.endswith("Z") else since
        q = q.where(FeedbackEvent.at >= datetime.fromisoformat(s))
    q = q.order_by(FeedbackEvent.at).limit(limit)
    return [_to_out(r) for r in db.execute(q).scalars().all()]
