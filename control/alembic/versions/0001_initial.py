"""initial schema — tenants, policies, policy_audit, bundles, detectors, profiles

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "policies",
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id"),
            primary_key=True,
        ),
        sa.Column("policy_id", sa.String(64), primary_key=True),
        sa.Column("version", sa.String(32), primary_key=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("document", postgresql.JSONB, nullable=False),
        sa.Column("document_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("parent_version", sa.String(32)),
        sa.Column("origin", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("origin_ref", postgresql.JSONB),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("approved_by", sa.String(128)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('draft','in_review','approved','deprecated','revoked')",
            name="policies_status_ck",
        ),
        sa.CheckConstraint(
            "origin IN ('manual','feed','synthesizer','autotuner')",
            name="policies_origin_ck",
        ),
    )

    op.create_index(
        "policies_status_idx", "policies", ["tenant_id", "policy_id", "status"]
    )

    op.create_table(
        "policy_audit",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("policy_id", sa.String(64), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("actor", sa.String(128), nullable=False),
        sa.Column("note", sa.Text),
        sa.Column(
            "at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "policy_audit_lookup_idx",
        "policy_audit",
        ["tenant_id", "policy_id", "version", "at"],
    )

    op.create_table(
        "bundles",
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("environment", sa.String(32), primary_key=True),
        sa.Column("bundle_seq", sa.BigInteger, primary_key=True),
        sa.Column("manifest", postgresql.JSONB, nullable=False),
        sa.Column("manifest_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("signature", sa.LargeBinary, nullable=False),
        sa.Column("signing_key_id", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    op.create_table(
        "detectors",
        sa.Column("detector_id", sa.String(64), primary_key=True),
        sa.Column("version", sa.String(32), primary_key=True),
        sa.Column("scenario", sa.String(32), nullable=False),
        sa.Column("image_digest", sa.String(128), nullable=False),
        sa.Column("config_schema", postgresql.JSONB, nullable=False),
        sa.Column("benchmark", postgresql.JSONB),
    )

    op.create_table(
        "profiles",
        sa.Column("profile_id", sa.String(64), primary_key=True),
        sa.Column("version", sa.String(32), primary_key=True),
        sa.Column("document", postgresql.JSONB, nullable=False),
        sa.Column("signature", sa.LargeBinary, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("profiles")
    op.drop_table("detectors")
    op.drop_table("bundles")
    op.drop_index("policy_audit_lookup_idx", table_name="policy_audit")
    op.drop_table("policy_audit")
    op.drop_index("policies_status_idx", table_name="policies")
    op.drop_table("policies")
    op.drop_table("tenants")
