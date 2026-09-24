"""Create durable manager session identity and object bindings."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001_session"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sandbox_session",
        sa.Column("session_id", sa.Uuid(), primary_key=True),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False, unique=True),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("golden_version", sa.String(), nullable=False),
        sa.Column("pvc_uid", sa.String(), nullable=True),
        sa.Column("pvc_id", sa.Uuid(), nullable=True),
        sa.Column("service_deadline", sa.DateTime(timezone=True), nullable=True),
        sa.Column("guest_deployment_uid", sa.String(), nullable=True),
        sa.Column("ipc_deployment_uid", sa.String(), nullable=True),
        sa.Column("ipc_pvc_uid", sa.String(), nullable=True),
        sa.Column("ca_attempt", sa.Uuid(), nullable=True),
        sa.Column("ca_sources", JSONB(), nullable=True),
        sa.Column("ca_clones", JSONB(), nullable=True),
        sa.Column("claimed_by", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_execution_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_ping_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ping_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','creating','ready','shutting_down',"
            "'stopped','service','failed','recovering')",
            name="sandbox_session_status",
        ),
    )
    op.create_table(
        "session_pvc",
        sa.Column("pvc_id", sa.Uuid(), primary_key=True),
        sa.Column(
            "session_id",
            sa.Uuid(),
            sa.ForeignKey("sandbox_session.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False),
        sa.Column("uid", sa.String(), nullable=True),
        sa.Column("release_evidence", JSONB(), nullable=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("last_execution", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_state_change", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "state IN ('detached','attaching','attached','detaching','destroying','failed')",
            name="session_pvc_state",
        ),
    )
    op.create_index("ix_session_pvc_session_id", "session_pvc", ["session_id"])
    op.create_table(
        "cleanup_work",
        sa.Column("work_id", sa.Uuid(), primary_key=True),
        sa.Column(
            "session_id",
            sa.Uuid(),
            sa.ForeignKey("sandbox_session.session_id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False),
        sa.Column("pvc_id", sa.Uuid(), nullable=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("state_changed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("pvc_changed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("targets", JSONB(), nullable=False),
        sa.Column("pair_snapshot", JSONB(), nullable=True),
    )
    op.create_index("ix_cleanup_work_session_id", "cleanup_work", ["session_id"])
    op.create_table(
        "ping_probe",
        sa.Column("ping_id", sa.Uuid(), primary_key=True),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ping_probe_sandbox_id", "ping_probe", ["sandbox_id"])
    # Egress uses a fresh installation, not adoption of historical object names.
    # Deliberately no session FK/cascade: losing a session must not erase ownership.
    op.create_table(
        "sandbox_pair_intent",
        sa.Column("generation", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("claim_owner", sa.Uuid(), nullable=False),
        sa.Column("claim_changed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("namespace", sa.String(), nullable=False),
        sa.Column("golden_version", sa.String(), nullable=False),
        sa.Column("control_uids", JSONB(), nullable=False),
        sa.Column("creation_fenced", sa.Boolean(), nullable=False),
        sa.Column("control_dispatch", JSONB(), nullable=False),
        sa.Column("compute_uids", JSONB(), nullable=False),
        sa.Column("compute_dispatch", JSONB(), nullable=False),
        sa.Column("compute_payloads", JSONB(), nullable=False),
        sa.Column("relay_custody", JSONB(), nullable=False),
        sa.Column("relay_inputs", JSONB(), nullable=False),
        sa.Column("egress_state_id", sa.Uuid(), nullable=True),
        sa.Column("ipc_resources", JSONB(), nullable=False),
        sa.Column("volume_resources", JSONB(), nullable=False),
        sa.Column("topics_dispatch", sa.String(), nullable=False),
        sa.Column("cleanup_journal", JSONB(), nullable=True),
        sa.UniqueConstraint("sandbox_id", name="sandbox_pair_intent_sandbox"),
        sa.UniqueConstraint(
            "session_id", "claim_owner", "claim_changed", name="sandbox_pair_intent_claim"
        ),
    )
    op.create_index("ix_sandbox_pair_intent_session_id", "sandbox_pair_intent", ["session_id"])
    # Persistent sandbox identity and key commitment survive all attachment rows.
    op.create_table(
        "sandbox_egress_state",
        sa.Column("state_id", sa.Uuid(), primary_key=True),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("sandbox_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("creator_generation", sa.Uuid(), nullable=False),
        sa.Column("claim_owner", sa.Uuid(), nullable=False),
        sa.Column("claim_changed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("namespace", sa.String(), nullable=False),
        sa.Column("storage_bytes", sa.BigInteger(), nullable=False),
        sa.Column("key_fingerprint", sa.String(), nullable=False),
        sa.Column("key_dispatch", sa.String(), nullable=False),
        sa.Column("key_uid", sa.String(), nullable=True),
        sa.Column("volume_dispatch", sa.String(), nullable=False),
        sa.Column("volume_uid", sa.String(), nullable=True),
        sa.UniqueConstraint("sandbox_id", name="sandbox_egress_state_sandbox"),
    )
    op.create_index("ix_sandbox_egress_state_session_id", "sandbox_egress_state", ["session_id"])


def downgrade() -> None:
    op.drop_table("sandbox_egress_state")
    op.drop_table("sandbox_pair_intent")
    op.drop_table("ping_probe")
    op.drop_table("cleanup_work")
    op.drop_table("session_pvc")
    op.drop_table("sandbox_session")
