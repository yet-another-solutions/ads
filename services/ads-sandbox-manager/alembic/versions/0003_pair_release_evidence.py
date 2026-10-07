"""Persist stored release evidence on the persistent egress volume row."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0003_pair_release_evidence"
down_revision = "0002_ping_publication"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Pair-intent evidence lives inside the existing JSONB resource entries.
    # Only the egress-state row needs an explicit column; NULL stays
    # not-captured and fails closed at teardown, exactly like a missing key.
    op.add_column(
        "sandbox_egress_state",
        sa.Column("volume_release", JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sandbox_egress_state", "volume_release")
