"""Create active_sessions.

Revision ID: 0001_active_sessions
Revises:
Create Date: 2026-09-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_active_sessions"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "active_sessions",
        sa.Column("session_id", sa.String(length=36), primary_key=True),
        sa.Column("message_id", sa.String(length=36), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("active_sessions")
