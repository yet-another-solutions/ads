from __future__ import annotations

from datetime import UTC, datetime

from ads_audit.models import TABLE, audit_decisions
from ads_audit.schema import CREATE_TABLE, create_partition, month_bounds, partition_name


def test_the_journal_is_partitioned_by_time() -> None:
    """Retention drops a partition, so the table must be ranged on the timestamp."""
    assert "PARTITION BY RANGE (recorded_at)" in CREATE_TABLE
    assert "PRIMARY KEY (recorded_at, id)" in CREATE_TABLE


def test_the_written_row_carries_the_time_the_index_is_keyed_on() -> None:
    """A redelivery only conflicts if recorded_at comes from the event, not from now()."""
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
    } <= columns


def test_the_journal_says_which_check_produced_the_row() -> None:
    """One call can leave two rows — the matrix permitted it, the payload refused it."""
    assert "point" in CREATE_TABLE
    assert "DEFAULT 'call'" in CREATE_TABLE
