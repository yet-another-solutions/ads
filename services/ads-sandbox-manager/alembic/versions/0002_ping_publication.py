"""Distinguish prepared ping correlation from acknowledged publication."""

import sqlalchemy as sa
from alembic import op

revision = "0002_ping_publication"
down_revision = "0001_session"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing probes have unknown publication outcome; never infer delivery.
    op.add_column("ping_probe", sa.Column("published_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("ping_probe", "published_at")
