import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class PolicyStatus(str, enum.Enum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class PolicyOrigin(str, enum.Enum):
    MANUAL = "manual"
    FEED = "feed"
    SYNTHESIZER = "synthesizer"
    AUTOTUNER = "autotuner"


class AuditAction(str, enum.Enum):
    CREATED = "created"
    SUBMITTED = "submitted"
    APPROVED = "approved"
    REJECTED = "rejected"
    PROMOTED = "promoted"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','in_review','approved','deprecated','revoked')",
            name="policies_status_ck",
        ),
        CheckConstraint(
            "origin IN ('manual','feed','synthesizer','autotuner')",
            name="policies_origin_ck",
        ),
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), primary_key=True
    )
    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    document: Mapped[dict] = mapped_column(JSONB, nullable=False)
    document_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    parent_version: Mapped[Optional[str]] = mapped_column(String(32))
    origin: Mapped[str] = mapped_column(String(16), nullable=False, default=PolicyOrigin.MANUAL.value)
    origin_ref: Mapped[Optional[dict]] = mapped_column(JSONB)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    approved_by: Mapped[Optional[str]] = mapped_column(String(128))
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    change_class: Mapped[Optional[str]] = mapped_column(String(32))
    auto_approval_rule: Mapped[Optional[str]] = mapped_column(String(64))


class PolicyAudit(Base):
    __tablename__ = "policy_audit"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
