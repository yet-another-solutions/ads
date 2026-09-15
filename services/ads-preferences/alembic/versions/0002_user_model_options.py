"""Add type-specific options on user_model.

Revision ID: 0002_user_model_options
Revises: 0001_user_model
Create Date: 2026-09-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_user_model_options"
down_revision: str | None = "0001_user_model"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user_model",
        sa.Column("options", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.execute(
        sa.text(
            "UPDATE user_model "
            "SET options = jsonb_build_object('model-name', name) "
            "WHERE options IS NULL"
        )
    )
    op.alter_column("user_model", "options", nullable=False)


def downgrade() -> None:
    op.drop_column("user_model", "options")
