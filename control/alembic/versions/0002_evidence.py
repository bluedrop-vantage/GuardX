"""evidence store — guard_decisions + chain_anchors

Revision ID: 0002_evidence
Revises: 0001_initial
Create Date: 2026-07-16

Design notes (spec §4.4):
  * Append-only. There is no UPDATE / DELETE on guard_decisions.
  * Hash chain per (tenant, app): each event stores prev_event_hash + event_hash.
  * chain_anchors carry a signed head hash for a (tenant, app, date) window;
    together with the row-level chain this proves no event was inserted,
    altered, or deleted after anchoring (auditor evidence).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0002_evidence"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "guard_decisions",
        sa.Column("event_id", sa.String(64), primary_key=True),
        sa.Column("tenant", sa.String(64), nullable=False),
        sa.Column("app", sa.String(64), nullable=False),
        sa.Column("env", sa.String(32), nullable=False),
        sa.Column("chain_seq", sa.BigInteger, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_id", sa.String(64), nullable=False),
        sa.Column("policy", sa.String(128), nullable=False),
        sa.Column("bundle_seq", sa.BigInteger, nullable=False),
        sa.Column("guard_id", sa.String(64)),
        sa.Column("scenario", sa.String(32)),
        sa.Column("detector", sa.String(128)),
        sa.Column("direction", sa.String(8)),
        sa.Column("verdict", sa.String(24), nullable=False),
        sa.Column("score", sa.Float),
        sa.Column("action_taken", sa.String(64)),
        sa.Column("latency_ms", sa.BigInteger),
        sa.Column("evidence_mode", sa.String(16), nullable=False, server_default="spans"),
        sa.Column("spans", postgresql.JSONB),
        sa.Column("text_hash", sa.String(80)),        # "sha256:<hex>"
        sa.Column("prev_event_hash", sa.String(80)),
        sa.Column("event_hash", sa.String(80), nullable=False),
        sa.Column("payload_ref", sa.String(256)),      # for evidence_mode=full_text (deferred)
        sa.CheckConstraint(
            "evidence_mode IN ('none','spans','full_text')",
            name="guard_decisions_evidence_mode_ck",
        ),
    )
    # Reads are always (tenant, app, ts) or (tenant, app, chain_seq).
    op.create_index(
        "guard_decisions_scan_idx",
        "guard_decisions",
        ["tenant", "app", "chain_seq"],
        unique=True,
    )
    op.create_index(
        "guard_decisions_time_idx",
        "guard_decisions",
        ["tenant", "app", "ts"],
    )

    # A row per (tenant, app) tracks the current chain head so appends stay O(1).
    op.create_table(
        "guard_decision_heads",
        sa.Column("tenant", sa.String(64), primary_key=True),
        sa.Column("app", sa.String(64), primary_key=True),
        sa.Column("chain_seq", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("event_hash", sa.String(80)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Signed anchor covers a chain window (start_seq..end_seq inclusive).
    op.create_table(
        "chain_anchors",
        sa.Column("tenant", sa.String(64), primary_key=True),
        sa.Column("app", sa.String(64), primary_key=True),
        sa.Column("anchor_at", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("start_seq", sa.BigInteger, nullable=False),
        sa.Column("end_seq", sa.BigInteger, nullable=False),
        sa.Column("head_hash", sa.String(80), nullable=False),
        sa.Column("signature", sa.LargeBinary, nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("chain_anchors")
    op.drop_table("guard_decision_heads")
    op.drop_index("guard_decisions_time_idx", table_name="guard_decisions")
    op.drop_index("guard_decisions_scan_idx", table_name="guard_decisions")
    op.drop_table("guard_decisions")
