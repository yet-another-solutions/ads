from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.dialects import postgresql

from ads_audit.models import TABLE, audit_decisions
from ads_audit.repository import deny_budget_statement
from ads_audit.schema import (
    ADD_CONVERSATION,
    ADD_DECIDED_BY,
    ADD_SOURCE,
    ADD_TOOL,
    CREATE_BLOCKS_TABLE,
    CREATE_CONVERSATION_INDEX,
    CREATE_SOURCE_INDEX,
    CREATE_TABLE,
    create_partition,
    month_bounds,
    partition_name,
)


def test_the_journal_is_partitioned_by_time_so_retention_can_drop_a_partition() -> None:
    assert "PARTITION BY RANGE (recorded_at)" in CREATE_TABLE
    assert "PRIMARY KEY (recorded_at, id)" in CREATE_TABLE


def test_the_written_row_takes_recorded_at_from_the_event_so_a_redelivery_conflicts() -> None:
    statement = audit_decisions.insert().values(
        recorded_at=datetime(2026, 9, 14, tzinfo=UTC),
        event_id="e1",
        run_id="run-1",
        subject="alice",
        capability="secret.read",
        resource="ads-client-secret",
        effect="deny",
        rule_id="secret.read",
        weight=5,
        policy_hash="hash",
        content=None,
    )
    written = set(statement.compile().binds)
    assert "recorded_at" in written
    assert {"recorded_at", "event_id"} <= written


def test_the_deny_budget_is_summed_by_the_database_not_by_pulling_the_events() -> None:
    statement = deny_budget_statement(audit_decisions.c.conversation == "chat", 3)
    sql = str(statement.compile(dialect=postgresql.dialect()))
    assert "sum(CASE WHEN" in sql
    assert (
        "row_number() OVER (PARTITION BY audit_decisions.capability, audit_decisions.resource"
        in sql
    )
    assert "ORDER BY audit_decisions.recorded_at, audit_decisions.id)" in sql
    assert "audit_decisions.effect =" in sql


def test_month_bounds_roll_over_the_year() -> None:
    assert month_bounds(datetime(2026, 9, 14, tzinfo=UTC)) == (
        datetime(2026, 9, 1).date(),
        datetime(2026, 10, 1).date(),
    )
    assert month_bounds(datetime(2026, 12, 31, tzinfo=UTC)) == (
        datetime(2026, 12, 1).date(),
        datetime(2027, 1, 1).date(),
    )


def test_a_partition_covers_exactly_its_month() -> None:
    start, end = month_bounds(datetime(2026, 9, 14, tzinfo=UTC))
    statement = create_partition(start, end)
    assert partition_name(start) == f"{TABLE}_2026_09"
    assert "FOR VALUES FROM ('2026-09-01') TO ('2026-10-01')" in statement


def test_the_table_carries_what_the_event_carries() -> None:
    columns = set(audit_decisions.c.keys())
    assert {
        "event_id",
        "run_id",
        "subject",
        "capability",
        "resource",
        "effect",
        "rule_id",
        "weight",
        "policy_hash",
        "content",
        "point",
        "decided_by",
        "conversation",
        "source",
        "tool",
    } <= columns


def test_an_existing_journal_gets_where_each_call_went() -> None:
    assert "ADD COLUMN IF NOT EXISTS source" in ADD_SOURCE
    assert "ADD COLUMN IF NOT EXISTS tool" in ADD_TOOL
    assert "(source, recorded_at)" in CREATE_SOURCE_INDEX


def test_the_journal_says_which_check_produced_the_row() -> None:
    assert "point" in CREATE_TABLE
    assert "DEFAULT 'call'" in CREATE_TABLE


def test_the_journal_says_which_build_wrote_the_row() -> None:
    assert "decided_by" in CREATE_TABLE


def test_the_journal_says_which_conversation_the_row_belongs_to() -> None:
    assert "conversation varchar(64)" in CREATE_TABLE
    assert "ADD COLUMN IF NOT EXISTS conversation" in ADD_CONVERSATION
    assert "(conversation)" in CREATE_CONVERSATION_INDEX


def test_conversation_blocks_live_in_their_own_table() -> None:
    assert "CREATE TABLE IF NOT EXISTS conversation_blocks" in CREATE_BLOCKS_TABLE
    assert "conversation  varchar(64) PRIMARY KEY" in CREATE_BLOCKS_TABLE
    assert "PARTITION" not in CREATE_BLOCKS_TABLE
    assert "lifted_by" in CREATE_BLOCKS_TABLE


def test_an_existing_journal_without_the_build_column_gets_it_added() -> None:
    assert "ADD COLUMN IF NOT EXISTS decided_by" in ADD_DECIDED_BY
    assert "DEFAULT ''" in ADD_DECIDED_BY
