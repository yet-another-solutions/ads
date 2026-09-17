"""Create durable manager session identity and object bindings."""

import sqlalchemy as sa
from alembic import op

revision = "0001_session"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_session",
        sa.Column("session_id", sa.Uuid(), primary_key=True),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("golden_version", sa.String(), nullable=False),
        sa.Column("pvc_uid", sa.String(), nullable=True),
        sa.Column("guest_deployment_uid", sa.String(), nullable=True),
        sa.Column("ipc_deployment_uid", sa.String(), nullable=True),
        sa.Column("ipc_pvc_uid", sa.String(), nullable=True),
        sa.Column("claimed_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_execution_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_ping_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','creating','ready','shutting_down',"
            "'stopped','failed','recovering')",
            name="sandbox_session_status",
        ),
    )


def downgrade() -> None:
    op.drop_table("sandbox_session")
