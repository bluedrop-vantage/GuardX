"""shadow-mode diagnostic flag on guard_decisions

Revision ID: 0003_shadow_flag
Revises: 0002_evidence
Create Date: 2026-07-17

Deliberately NOT in CHAIN_FIELDS: the chain proves what a detector said, not
what the gateway did about it. is_shadow is a diagnostic column derived from
the policy shape at bundle_seq — auditors can join back to reconstruct.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_shadow_flag"
down_revision: Union[str, None] = "0002_evidence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "guard_decisions",
        sa.Column("is_shadow", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index(
        "guard_decisions_shadow_idx",
        "guard_decisions",
        ["tenant", "app", "is_shadow"],
    )


def downgrade() -> None:
    op.drop_index("guard_decisions_shadow_idx", table_name="guard_decisions")
    op.drop_column("guard_decisions", "is_shadow")
