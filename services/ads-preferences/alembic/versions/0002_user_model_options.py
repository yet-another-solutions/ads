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
from sqlalchemy.types import JSON

revision: str = "0002_user_model_options"
down_revision: str | None = "0001_user_model"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = postgresql.JSONB(astext_type=sa.Text()).with_variant(JSON(), "sqlite")


def upgrade() -> None:
    op.add_column("user_model", sa.Column("options", _JSON, nullable=True))
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            sa.text(
                "UPDATE user_model "
                "SET options = json_object('model-name', name) "
                "WHERE options IS NULL"
            )
        )
        with op.batch_alter_table("user_model") as batch_op:
            batch_op.alter_column("options", existing_type=_JSON, nullable=False)
        return
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
