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

metadata = MetaData()

audit_decisions = Table(
    TABLE,
    metadata,
    Column("id", BigInteger, primary_key=True, autoincrement=True),
    Column("recorded_at", DateTime(timezone=True), primary_key=True, server_default=func.now()),
    Column("event_id", String(64), nullable=False),
    Column("run_id", String(64), nullable=False),
    Column("subject", String(255), nullable=False),
    Column("capability", String(64), nullable=False),
    Column("resource", Text, nullable=False),
    Column("effect", String(16), nullable=False),
    Column("rule_id", String(64), nullable=False),
    Column("weight", Integer, nullable=False),
    Column("policy_hash", String(64), nullable=False),
    Column("content", Text, nullable=True),
    Column("point", String(16), nullable=False, server_default="call"),
)
