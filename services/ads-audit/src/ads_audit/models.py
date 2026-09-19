from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    func,
)

TABLE = "audit_decisions"
BLOCKS_TABLE = "conversation_blocks"

metadata = MetaData()

audit_decisions = Table(
    TABLE,
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("recorded_at", DateTime(timezone=True), primary_key=True, server_default=func.now()),
    Column("event_id", String(64), nullable=False),
    Column("run_id", String(64), nullable=False),
    Column("subject", String(255), nullable=False),
    Column("capability", String(64), nullable=True),
    Column("resource", Text, nullable=False),
    Column("effect", String(16), nullable=False),
    Column("rule_id", String(64), nullable=False),
    Column("weight", Integer, nullable=False),
    Column("policy_hash", String(64), nullable=False),
    Column("content", Text, nullable=True),
    Column("point", String(16), nullable=False, server_default="call"),
    Column("decided_by", String(128), nullable=False, server_default=""),
    Column("conversation", String(64), nullable=False, server_default=""),
)

conversation_blocks = Table(
    BLOCKS_TABLE,
    metadata,
    Column("conversation", String(64), primary_key=True),
    Column("blocked_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    Column("budget", Integer, nullable=False),
    Column("lifted_at", DateTime(timezone=True)),
    Column("lifted_by", String(128)),
    Column("lifted_budget", Integer),
)
