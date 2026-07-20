from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    LargeBinary,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class GuardDecision(Base):
    """Append-only decision event (spec §4.4).

    `chain_seq` + `event_hash` + `prev_event_hash` form a per-(tenant, app) hash
    chain: any insert/delete/edit breaks the chain and is detectable by the
    verifier CLI.
    """

    __tablename__ = "guard_decisions"
    __table_args__ = (
        CheckConstraint(
            "evidence_mode IN ('none','spans','full_text')",
            name="guard_decisions_evidence_mode_ck",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False)
    app: Mapped[str] = mapped_column(String(64), nullable=False)
    env: Mapped[str] = mapped_column(String(32), nullable=False)
    chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy: Mapped[str] = mapped_column(String(128), nullable=False)
    bundle_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    guard_id: Mapped[Optional[str]] = mapped_column(String(64))
    scenario: Mapped[Optional[str]] = mapped_column(String(32))
    detector: Mapped[Optional[str]] = mapped_column(String(128))
    direction: Mapped[Optional[str]] = mapped_column(String(8))
    verdict: Mapped[str] = mapped_column(String(24), nullable=False)
    score: Mapped[Optional[float]] = mapped_column(Float)
    action_taken: Mapped[Optional[str]] = mapped_column(String(64))
    latency_ms: Mapped[Optional[int]] = mapped_column(BigInteger)
    evidence_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="spans")
    spans: Mapped[Optional[list]] = mapped_column(JSONB)
    text_hash: Mapped[Optional[str]] = mapped_column(String(80))
    prev_event_hash: Mapped[Optional[str]] = mapped_column(String(80))
    event_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    payload_ref: Mapped[Optional[str]] = mapped_column(String(256))
    is_shadow: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class GuardDecisionHead(Base):
    """One row per (tenant, app) tracking the current chain head."""

    __tablename__ = "guard_decision_heads"

    tenant: Mapped[str] = mapped_column(String(64), primary_key=True)
    app: Mapped[str] = mapped_column(String(64), primary_key=True)
    chain_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    event_hash: Mapped[Optional[str]] = mapped_column(String(80))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ChainAnchor(Base):
    """Signed head over a (tenant, app, window) — the auditor deliverable."""

    __tablename__ = "chain_anchors"

    tenant: Mapped[str] = mapped_column(String(64), primary_key=True)
    app: Mapped[str] = mapped_column(String(64), primary_key=True)
    anchor_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    start_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    end_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
