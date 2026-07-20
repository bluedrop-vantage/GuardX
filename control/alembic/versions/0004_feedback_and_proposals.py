"""feedback events + proposal change_class

Revision ID: 0004_feedback_and_proposals
Revises: 0003_shadow_flag
Create Date: 2026-07-17

Two structural pieces M5 needs:

  * `feedback_events` — thumbs / analyst dispositions / appeal outcomes.
    Foreign key by (tenant, event_id) into guard_decisions so we can join
    a labeled disposition to the original decision without duplicating data.
  * `policies.change_class` — governs auto-approval eligibility. Only
    `monotonic_add` (adding new detection patterns without changing
    thresholds/actions) is auto-approvable, and only when origin=feed.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0004_feedback_and_proposals"
down_revision: Union[str, None] = "0003_shadow_flag"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "feedback_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant", sa.String(64), nullable=False),
        sa.Column("app", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(64)),          # references guard_decisions.event_id (soft FK; may be null for unassigned)
        sa.Column("guard_id", sa.String(64)),
        sa.Column("policy", sa.String(128)),
        sa.Column("source", sa.String(32), nullable=False),      # "user_thumbs" | "analyst" | "appeal" | "autolabel"
        sa.Column("disposition", sa.String(32), nullable=False), # "true_positive" | "false_positive" | "true_negative" | "false_negative"
        sa.Column("note", sa.Text),
        sa.Column("submitted_by", sa.String(128), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "source IN ('user_thumbs','analyst','appeal','autolabel')",
            name="feedback_events_source_ck",
        ),
        sa.CheckConstraint(
            "disposition IN ('true_positive','false_positive','true_negative','false_negative')",
            name="feedback_events_disposition_ck",
        ),
    )
    op.create_index(
        "feedback_events_lookup_idx",
        "feedback_events",
        ["tenant", "app", "guard_id", "at"],
    )
    op.create_index(
        "feedback_events_event_idx",
        "feedback_events",
        ["tenant", "event_id"],
    )

    op.add_column("policies", sa.Column("change_class", sa.String(32)))
    op.add_column("policies", sa.Column("auto_approval_rule", sa.String(64)))


def downgrade() -> None:
    op.drop_column("policies", "auto_approval_rule")
    op.drop_column("policies", "change_class")
    op.drop_index("feedback_events_event_idx", table_name="feedback_events")
    op.drop_index("feedback_events_lookup_idx", table_name="feedback_events")
    op.drop_table("feedback_events")
