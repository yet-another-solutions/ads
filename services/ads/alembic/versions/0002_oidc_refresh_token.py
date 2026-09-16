"""Store Keycloak refresh tokens off the session cookie.

Revision ID: 0002_oidc_refresh_token
Revises: 0001_threadline
Create Date: 2026-09-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_oidc_refresh_token"
down_revision: str | None = "0001_threadline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_refresh_token",
        sa.Column("sid", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_token", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("oidc_refresh_token_user_id_idx", "oidc_refresh_token", ["user_id"])


def downgrade() -> None:
    op.drop_index("oidc_refresh_token_user_id_idx", table_name="oidc_refresh_token")
    op.drop_table("oidc_refresh_token")
