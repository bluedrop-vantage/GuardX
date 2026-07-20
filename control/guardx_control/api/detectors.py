"""Detector catalog.

Detectors are registry artifacts: a bundle pins them by (id, version, image
digest). Policies reference `id@version` in guard.detector — bundle build
fills in image_digest by looking up this catalog (spec §3.2).
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Detector
from .auth import Principal, Role, current_principal, require_role
from .deps import get_db

router = APIRouter(prefix="/v1/detectors", tags=["detectors"])


class DetectorIn(BaseModel):
    detector_id: str
    version: str
    scenario: str
    image_digest: str
    config_schema: dict[str, Any] = Field(default_factory=dict)
    benchmark: Optional[dict[str, Any]] = None


class DetectorOut(DetectorIn):
    pass


@router.get("", response_model=list[DetectorOut])
def list_detectors(
    db: Session = Depends(get_db),
    _: Principal = Depends(current_principal),
) -> list[DetectorOut]:
    rows = db.execute(select(Detector).order_by(Detector.detector_id, Detector.version)).scalars().all()
    return [
        DetectorOut(
            detector_id=r.detector_id, version=r.version, scenario=r.scenario,
            image_digest=r.image_digest, config_schema=r.config_schema, benchmark=r.benchmark,
        )
        for r in rows
    ]


@router.post("", response_model=DetectorOut, status_code=201)
def register_detector(
    body: DetectorIn,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role(Role.ADMIN)),
) -> DetectorOut:
    existing = db.get(Detector, (body.detector_id, body.version))
    if existing:
        raise HTTPException(409, f"{body.detector_id}@{body.version} already registered")
    row = Detector(
        detector_id=body.detector_id, version=body.version, scenario=body.scenario,
        image_digest=body.image_digest, config_schema=body.config_schema, benchmark=body.benchmark,
    )
    db.add(row)
    db.commit()
    return body
