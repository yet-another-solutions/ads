"""Create durable MCP in-flight executions."""

import sqlalchemy as sa
from alembic import op

revision = "0001_execution"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_execution",
        sa.Column("execution_id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("message_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("timed_out", sa.Boolean(), nullable=False),
        sa.Column("ack_replied", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_sandbox_execution_created_at", "sandbox_execution", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_sandbox_execution_created_at", table_name="sandbox_execution")
    op.drop_table("sandbox_execution")
