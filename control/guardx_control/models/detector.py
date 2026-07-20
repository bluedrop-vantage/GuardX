from typing import Optional

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from ..db import Base


class Detector(Base):
    __tablename__ = "detectors"

    detector_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(32), nullable=False)
    image_digest: Mapped[str] = mapped_column(String(128), nullable=False)
    config_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    benchmark: Mapped[Optional[dict]] = mapped_column(JSONB)
