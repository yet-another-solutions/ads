"""Create user_model catalog.

Revision ID: 0001_user_model
Revises:
Create Date: 2026-09-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.types import JSON

revision: str = "0001_user_model"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = postgresql.JSONB(astext_type=sa.Text()).with_variant(JSON(), "sqlite")


def upgrade() -> None:
    op.create_table(
        "user_model",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("authentication", _JSON, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("user_model_user_id_idx", "user_model", ["user_id"])


def downgrade() -> None:
    op.drop_index("user_model_user_id_idx", table_name="user_model")
    op.drop_table("user_model")
