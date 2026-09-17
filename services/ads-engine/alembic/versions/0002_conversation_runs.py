"""Create conversation_runs.

Revision ID: 0002_conversation_runs
Revises: 0001_active_sessions
Create Date: 2026-09-17
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_conversation_runs"
down_revision: str | None = "0001_active_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "conversation_runs",
        sa.Column("session_id", sa.String(length=36), primary_key=True),
        sa.Column("run_id", sa.String(length=64), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("conversation_runs")
