"""Evidence ingestion, query, and export (spec §4.4).

Gateway ⇒ ``POST /v1/evidence/events`` (batches). Auditors ⇒
``GET /v1/evidence/events`` and ``GET /v1/evidence:export``.

Hash-chain enforcement lives here: the head row's chain_seq + event_hash is
consulted under a SELECT FOR UPDATE, each incoming event's prev_event_hash
must equal the current head, and the head is advanced in the same
transaction as the insert. That is the property the verifier CLI later
re-derives without trusting anything but the events themselves.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..evidence import (
    CHAIN_FIELDS,
    canonical_event_bytes,
    compute_event_hash,
    minimize_event,
)
from ..models import ChainAnchor, GuardDecision, GuardDecisionHead
from ..signing import Ed25519Signer
from .auth import Principal, Role, current_principal, require_role
from .deps import get_db, get_signer

router = APIRouter(prefix="/v1/evidence", tags=["evidence"])


# -- request/response shapes ---------------------------------------------------

class SpanIn(BaseModel):
    start: int
    end: int
    label: str
    confidence: float


class EventIn(BaseModel):
    event_id: str
    ts: str                     # ISO-8601
    tenant: str
    app: str
    env: str
    request_id: str
    policy: str                 # id@version
    bundle_seq: int
    guard_id: Optional[str] = None
    scenario: Optional[str] = None
    detector: Optional[str] = None
    direction: Optional[str] = None
    verdict: str
    score: Optional[float] = None
    action_taken: Optional[str] = None
    latency_ms: Optional[int] = None
    evidence_mode: str = "spans"
    spans: Optional[list[SpanIn]] = None
    text_hash: Optional[str] = None
    is_shadow: bool = False


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(..., min_length=1, max_length=500)


class EventOut(EventIn):
    chain_seq: int
    prev_event_hash: Optional[str]
    event_hash: str


class IngestResult(BaseModel):
    accepted: int
    chain_head: dict[str, dict[str, Any]]  # (tenant/app) -> {chain_seq, event_hash}


# -- helpers -------------------------------------------------------------------

def _row_to_event(r: GuardDecision) -> dict[str, Any]:
    return {
        "event_id": r.event_id,
        "ts": r.ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tenant": r.tenant, "app": r.app, "env": r.env,
        "chain_seq": r.chain_seq,
        "request_id": r.request_id,
        "policy": r.policy, "bundle_seq": r.bundle_seq,
        "guard_id": r.guard_id, "scenario": r.scenario,
        "detector": r.detector, "direction": r.direction,
        "verdict": r.verdict, "score": r.score,
        "action_taken": r.action_taken, "latency_ms": r.latency_ms,
        "evidence_mode": r.evidence_mode, "spans": r.spans,
        "text_hash": r.text_hash,
        "prev_event_hash": r.prev_event_hash,
        "event_hash": r.event_hash,
        "is_shadow": bool(r.is_shadow),
    }


def _parse_ts(iso: str) -> datetime:
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    return datetime.fromisoformat(iso)


# -- ingestion -----------------------------------------------------------------

@router.post("/events", response_model=IngestResult, status_code=201)
def ingest(
    body: EventBatchIn,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(Role.SERVICE, Role.ADMIN)),
) -> IngestResult:
    # Bucket by (tenant, app) so we can lock one head row per bucket instead
    # of contending across the whole table.
    grouped: dict[tuple[str, str], list[EventIn]] = {}
    for e in body.events:
        grouped.setdefault((e.tenant, e.app), []).append(e)

    heads_out: dict[str, dict[str, Any]] = {}

    for (tenant, app), evts in grouped.items():
        # Sort within a bucket by ts to make the chain deterministic when the
        # gateway batches out-of-order emissions.
        evts.sort(key=lambda e: _parse_ts(e.ts))

        head = db.execute(
            select(GuardDecisionHead)
            .where(GuardDecisionHead.tenant == tenant, GuardDecisionHead.app == app)
            .with_for_update()
        ).scalar_one_or_none()
        if head is None:
            head = GuardDecisionHead(tenant=tenant, app=app, chain_seq=0, event_hash=None)
            db.add(head)
            db.flush()

        for e in evts:
            head.chain_seq += 1
            payload = e.model_dump()
            payload["chain_seq"] = head.chain_seq
            payload["prev_event_hash"] = head.event_hash
            payload = minimize_event(payload)
            payload["event_hash"] = compute_event_hash(payload)
            head.event_hash = payload["event_hash"]

            # Persist.
            row = GuardDecision(
                event_id=payload["event_id"],
                tenant=payload["tenant"], app=payload["app"], env=payload["env"],
                chain_seq=payload["chain_seq"],
                ts=_parse_ts(payload["ts"]),
                request_id=payload["request_id"],
                policy=payload["policy"], bundle_seq=payload["bundle_seq"],
                guard_id=payload["guard_id"], scenario=payload["scenario"],
                detector=payload["detector"], direction=payload["direction"],
                verdict=payload["verdict"], score=payload["score"],
                action_taken=payload["action_taken"], latency_ms=payload["latency_ms"],
                evidence_mode=payload["evidence_mode"],
                spans=payload.get("spans"),
                text_hash=payload["text_hash"],
                prev_event_hash=payload["prev_event_hash"],
                event_hash=payload["event_hash"],
                is_shadow=bool(e.is_shadow),
            )
            db.add(row)

        head.updated_at = datetime.now(timezone.utc)
        heads_out[f"{tenant}/{app}"] = {"chain_seq": head.chain_seq, "event_hash": head.event_hash}

    db.commit()
    return IngestResult(accepted=len(body.events), chain_head=heads_out)


# -- query --------------------------------------------------------------------

@router.get("/events", response_model=list[EventOut])
def list_events(
    tenant: str = Query(...),
    app: str = Query(...),
    since_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
) -> list[EventOut]:
    rows = db.execute(
        select(GuardDecision)
        .where(
            GuardDecision.tenant == tenant,
            GuardDecision.app == app,
            GuardDecision.chain_seq > since_seq,
        )
        .order_by(GuardDecision.chain_seq)
        .limit(limit)
    ).scalars().all()
    return [EventOut(**_row_to_event(r)) for r in rows]


class ChainVerifyReport(BaseModel):
    tenant: str
    app: str
    checked: int
    ok: bool
    first_bad_seq: Optional[int] = None
    reason: Optional[str] = None
    head: Optional[dict[str, Any]] = None


def _verify_chain_impl(db: Session, tenant: str, app: str) -> ChainVerifyReport:
    rows = db.execute(
        select(GuardDecision)
        .where(GuardDecision.tenant == tenant, GuardDecision.app == app)
        .order_by(GuardDecision.chain_seq)
    ).scalars().all()

    prev_hash: Optional[str] = None
    expected_seq = 1
    for r in rows:
        event = _row_to_event(r)
        if r.chain_seq != expected_seq:
            return ChainVerifyReport(
                tenant=tenant, app=app, checked=expected_seq - 1, ok=False,
                first_bad_seq=r.chain_seq,
                reason=f"seq gap: expected {expected_seq}, got {r.chain_seq}",
            )
        if event["prev_event_hash"] != prev_hash:
            return ChainVerifyReport(
                tenant=tenant, app=app, checked=expected_seq - 1, ok=False,
                first_bad_seq=r.chain_seq,
                reason="prev_event_hash mismatch",
            )
        recomputed = compute_event_hash(event)
        if recomputed != event["event_hash"]:
            return ChainVerifyReport(
                tenant=tenant, app=app, checked=expected_seq - 1, ok=False,
                first_bad_seq=r.chain_seq,
                reason="event_hash mismatch (canonical bytes differ)",
            )
        prev_hash = event["event_hash"]
        expected_seq += 1

    return ChainVerifyReport(
        tenant=tenant, app=app, checked=len(rows), ok=True,
        head={"chain_seq": len(rows), "event_hash": prev_hash},
    )


@router.get("/verify", response_model=ChainVerifyReport)
def verify_chain(
    tenant: str = Query(...),
    app: str = Query(...),
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
) -> ChainVerifyReport:
    return _verify_chain_impl(db, tenant, app)


# -- anchor -------------------------------------------------------------------

class ChainAnchorOut(BaseModel):
    tenant: str
    app: str
    anchor_at: str
    start_seq: int
    end_seq: int
    head_hash: str
    signature_b64: str
    signing_key_id: str


@router.post("/anchor", response_model=ChainAnchorOut, status_code=201)
def sign_anchor(
    tenant: str = Query(...),
    app: str = Query(...),
    db: Session = Depends(get_db),
    signer: Ed25519Signer = Depends(get_signer),
    _: Principal = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> ChainAnchorOut:
    head = db.execute(
        select(GuardDecisionHead).where(
            GuardDecisionHead.tenant == tenant, GuardDecisionHead.app == app
        )
    ).scalar_one_or_none()
    if head is None or head.chain_seq == 0:
        raise HTTPException(404, "no events for that (tenant, app) yet")

    # Find the previous anchor's end_seq so this anchor covers a fresh window.
    prev = db.execute(
        select(ChainAnchor)
        .where(ChainAnchor.tenant == tenant, ChainAnchor.app == app)
        .order_by(ChainAnchor.end_seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    start_seq = (prev.end_seq + 1) if prev else 1

    if head.chain_seq < start_seq:
        raise HTTPException(409, "chain has not advanced since last anchor")

    payload = {
        "tenant": tenant, "app": app,
        "start_seq": start_seq, "end_seq": head.chain_seq,
        "head_hash": head.event_hash,
    }
    from ..signing import canonical_json
    sig = signer.sign(canonical_json(payload))
    now = datetime.now(timezone.utc)
    row = ChainAnchor(
        tenant=tenant, app=app, anchor_at=now,
        start_seq=start_seq, end_seq=head.chain_seq,
        head_hash=head.event_hash,
        signature=sig, signing_key_id=signer.key_id,
    )
    db.add(row)
    db.commit()
    return ChainAnchorOut(
        tenant=tenant, app=app, anchor_at=now.isoformat(),
        start_seq=start_seq, end_seq=head.chain_seq,
        head_hash=head.event_hash,
        signature_b64=base64.b64encode(sig).decode("ascii"),
        signing_key_id=signer.key_id,
    )


# -- export -------------------------------------------------------------------

class ExportBundle(BaseModel):
    tenant: str
    app: str
    from_ts: Optional[str] = None
    to_ts: Optional[str] = None
    events: list[EventOut]
    anchors: list[ChainAnchorOut]
    verification: ChainVerifyReport


@router.get("/export", response_model=ExportBundle)
def export_bundle(
    tenant: str = Query(...),
    app: str = Query(...),
    from_ts: Optional[str] = Query(default=None, alias="from"),
    to_ts: Optional[str] = Query(default=None, alias="to"),
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(Role.APPROVER, Role.ADMIN)),
) -> ExportBundle:
    q = select(GuardDecision).where(GuardDecision.tenant == tenant, GuardDecision.app == app)
    if from_ts:
        q = q.where(GuardDecision.ts >= _parse_ts(from_ts))
    if to_ts:
        q = q.where(GuardDecision.ts <= _parse_ts(to_ts))
    q = q.order_by(GuardDecision.chain_seq)
    rows = db.execute(q).scalars().all()

    anchors = db.execute(
        select(ChainAnchor).where(ChainAnchor.tenant == tenant, ChainAnchor.app == app)
        .order_by(ChainAnchor.anchor_at)
    ).scalars().all()

    verification = _verify_chain_impl(db, tenant, app)
    return ExportBundle(
        tenant=tenant, app=app,
        from_ts=from_ts, to_ts=to_ts,
        events=[EventOut(**_row_to_event(r)) for r in rows],
        anchors=[
            ChainAnchorOut(
                tenant=a.tenant, app=a.app, anchor_at=a.anchor_at.isoformat(),
                start_seq=a.start_seq, end_seq=a.end_seq, head_hash=a.head_hash,
                signature_b64=base64.b64encode(a.signature).decode("ascii"),
                signing_key_id=a.signing_key_id,
            )
            for a in anchors
        ],
        verification=verification,
    )
