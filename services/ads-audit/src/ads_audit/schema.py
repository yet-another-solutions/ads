from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from ads_audit.models import TABLE

CREATE_TABLE = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id          bigserial,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    event_id    varchar(64) NOT NULL,
    run_id      varchar(64) NOT NULL,
    subject     varchar(255) NOT NULL,
    capability  varchar(64) NOT NULL,
    resource    text NOT NULL,
    effect      varchar(16) NOT NULL,
    rule_id     varchar(64) NOT NULL,
    weight      integer NOT NULL,
    policy_hash varchar(64) NOT NULL,
    content     text,
    point       varchar(16) NOT NULL DEFAULT 'call',
    PRIMARY KEY (recorded_at, id)
) PARTITION BY RANGE (recorded_at)
"""

#: Redelivery from the broker must not double-count a denial in the budget.
CREATE_UNIQUE = f"""
CREATE UNIQUE INDEX IF NOT EXISTS {TABLE}_event_id_key
ON {TABLE} (recorded_at, event_id)
"""

CREATE_RUN_INDEX = f"CREATE INDEX IF NOT EXISTS {TABLE}_run_idx ON {TABLE} (run_id)"
CREATE_SUBJECT_INDEX = f"CREATE INDEX IF NOT EXISTS {TABLE}_subject_idx ON {TABLE} (subject)"


def month_bounds(moment: datetime) -> tuple[date, date]:
    start = date(moment.year, moment.month, 1)
    end = date(start.year + 1, 1, 1) if start.month == 12 else date(start.year, start.month + 1, 1)
    return start, end


def partition_name(start: date) -> str:
    return f"{TABLE}_{start:%Y_%m}"


def create_partition(start: date, end: date) -> str:
    return (
        f"CREATE TABLE IF NOT EXISTS {partition_name(start)} "
        f"PARTITION OF {TABLE} FOR VALUES FROM ('{start}') TO ('{end}')"
    )


async def ensure_schema(connection: AsyncConnection, months_ahead: int = 2) -> None:
    """Create the journal and the partitions it will land in. Never drops anything."""
    await connection.execute(text(CREATE_TABLE))
    await connection.execute(text(CREATE_UNIQUE))
    await connection.execute(text(CREATE_RUN_INDEX))
    await connection.execute(text(CREATE_SUBJECT_INDEX))
    moment = datetime.now(UTC)
    for _ in range(months_ahead + 1):
        start, end = month_bounds(moment)
        await connection.execute(text(create_partition(start, end)))
        moment = datetime(end.year, end.month, 1, tzinfo=UTC)
