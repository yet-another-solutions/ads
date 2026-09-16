"""Create the Threadline domain: project, session, entry list, run, run buffer.

Revision ID: 0001_threadline
Revises:
Create Date: 2026-09-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_threadline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IN_FLIGHT = "status IN ('pending', 'running', 'finishing')"


def upgrade() -> None:
    op.create_table(
        "project",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("project_user_id_idx", "project", ["user_id"])
    op.create_table(
        "session",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("latest_entry_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"], name="session_project_fk"),
    )
    op.create_index("session_project_id_idx", "session", ["project_id"])
    op.create_index("session_user_id_idx", "session", ["user_id"])
    op.create_table(
        "session_entry",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("prev_id", sa.Uuid(), nullable=True),
        sa.Column("next_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=True),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("run_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["session.id"], name="session_entry_session_fk"),
        sa.ForeignKeyConstraint(["prev_id"], ["session_entry.id"], name="session_entry_prev_fk"),
        sa.ForeignKeyConstraint(["next_id"], ["session_entry.id"], name="session_entry_next_fk"),
    )
    op.create_index("session_entry_session_id_idx", "session_entry", ["session_id"])
    if op.get_bind().dialect.name != "sqlite":
        op.create_foreign_key(
            "session_latest_entry_fk",
            "session",
            "session_entry",
            ["latest_entry_id"],
            ["id"],
            deferrable=True,
            initially="DEFERRED",
        )
    op.create_table(
        "session_run",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("user_entry_id", sa.Uuid(), nullable=False),
        sa.Column("model_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("watermark", sa.Integer(), nullable=False),
        sa.Column("last_order", sa.Integer(), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finish_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_text", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["session.id"], name="session_run_session_fk"),
        sa.ForeignKeyConstraint(
            ["user_entry_id"],
            ["session_entry.id"],
            name="session_run_user_entry_fk",
        ),
    )
    op.create_index(
        "session_run_one_inflight",
        "session_run",
        ["session_id"],
        unique=True,
        postgresql_where=sa.text(_IN_FLIGHT),
        sqlite_where=sa.text(_IN_FLIGHT),
    )
    op.create_index("session_run_session_id_idx", "session_run", ["session_id"])
    op.create_table(
        "session_run_buffer",
        sa.Column("run_id", sa.Uuid(), primary_key=True),
        sa.Column("order_no", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["session_run.id"],
            name="session_run_buffer_run_fk",
        ),
    )


def downgrade() -> None:
    op.drop_table("session_run_buffer")
    op.drop_index("session_run_session_id_idx", table_name="session_run")
    op.drop_index("session_run_one_inflight", table_name="session_run")
    op.drop_table("session_run")
    if op.get_bind().dialect.name != "sqlite":
        op.drop_constraint("session_latest_entry_fk", "session", type_="foreignkey")
    op.drop_index("session_entry_session_id_idx", table_name="session_entry")
    op.drop_table("session_entry")
    op.drop_index("session_user_id_idx", table_name="session")
    op.drop_index("session_project_id_idx", table_name="session")
    op.drop_table("session")
    op.drop_index("project_user_id_idx", table_name="project")
    op.drop_table("project")
