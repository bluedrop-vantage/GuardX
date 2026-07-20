from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, CheckConstraint, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class FeedbackEvent(Base):
    """Labeled disposition for a decision event — the auto-tuner's raw input."""

    __tablename__ = "feedback_events"
    __table_args__ = (
        CheckConstraint(
            "source IN ('user_thumbs','analyst','appeal','autolabel')",
            name="feedback_events_source_ck",
        ),
        CheckConstraint(
            "disposition IN ('true_positive','false_positive','true_negative','false_negative')",
            name="feedback_events_disposition_ck",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant: Mapped[str] = mapped_column(String(64), nullable=False)
    app: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[Optional[str]] = mapped_column(String(64))
    guard_id: Mapped[Optional[str]] = mapped_column(String(64))
    policy: Mapped[Optional[str]] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    disposition: Mapped[str] = mapped_column(String(32), nullable=False)
    note: Mapped[Optional[str]] = mapped_column(Text)
    submitted_by: Mapped[str] = mapped_column(String(128), nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
