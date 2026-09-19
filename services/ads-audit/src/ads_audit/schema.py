from __future__ import annotations

from datetime import UTC, date, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from ads_audit.models import BLOCKS_TABLE, TABLE

CREATE_TABLE = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id          bigserial,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    event_id    varchar(64) NOT NULL,
    run_id      varchar(64) NOT NULL,
    subject     varchar(255) NOT NULL,
    capability  varchar(64),
    resource    text NOT NULL,
    effect      varchar(16) NOT NULL,
    rule_id     varchar(64) NOT NULL,
    weight      integer NOT NULL,
    policy_hash varchar(64) NOT NULL,
    content     text,
    point       varchar(16) NOT NULL DEFAULT 'call',
    decided_by  varchar(128) NOT NULL DEFAULT '',
    conversation varchar(64) NOT NULL DEFAULT '',
    PRIMARY KEY (recorded_at, id)
) PARTITION BY RANGE (recorded_at)
"""

ADD_DECIDED_BY = (
    f"ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS decided_by varchar(128) NOT NULL DEFAULT ''"
)

ADD_CONVERSATION = (
    f"ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS conversation varchar(64) NOT NULL DEFAULT ''"
)

CREATE_BLOCKS_TABLE = f"""
CREATE TABLE IF NOT EXISTS {BLOCKS_TABLE} (
    conversation  varchar(64) PRIMARY KEY,
    blocked_at    timestamptz NOT NULL DEFAULT now(),
    budget        integer NOT NULL,
    lifted_at     timestamptz,
    lifted_by     varchar(128),
    lifted_budget integer
)
"""

ADD_LIFTED_AT = f"ALTER TABLE {BLOCKS_TABLE} ADD COLUMN IF NOT EXISTS lifted_at timestamptz"
ADD_LIFTED_BY = f"ALTER TABLE {BLOCKS_TABLE} ADD COLUMN IF NOT EXISTS lifted_by varchar(128)"
ADD_LIFTED_BUDGET = f"ALTER TABLE {BLOCKS_TABLE} ADD COLUMN IF NOT EXISTS lifted_budget integer"

CREATE_UNIQUE_EVENT_INDEX = f"""
CREATE UNIQUE INDEX IF NOT EXISTS {TABLE}_event_id_key
ON {TABLE} (recorded_at, event_id)
"""

CREATE_RUN_INDEX = f"CREATE INDEX IF NOT EXISTS {TABLE}_run_idx ON {TABLE} (run_id)"
CREATE_SUBJECT_INDEX = f"CREATE INDEX IF NOT EXISTS {TABLE}_subject_idx ON {TABLE} (subject)"
CREATE_CONVERSATION_INDEX = (
    f"CREATE INDEX IF NOT EXISTS {TABLE}_conversation_idx ON {TABLE} (conversation)"
)


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
    await connection.execute(text(CREATE_TABLE))
    await connection.execute(text(ADD_DECIDED_BY))
    await connection.execute(text(ADD_CONVERSATION))
    await connection.execute(text(CREATE_UNIQUE_EVENT_INDEX))
    await connection.execute(text(CREATE_RUN_INDEX))
    await connection.execute(text(CREATE_SUBJECT_INDEX))
    await connection.execute(text(CREATE_CONVERSATION_INDEX))
    await connection.execute(text(CREATE_BLOCKS_TABLE))
    await connection.execute(text(ADD_LIFTED_AT))
    await connection.execute(text(ADD_LIFTED_BY))
    await connection.execute(text(ADD_LIFTED_BUDGET))
    moment = datetime.now(UTC)
    for _ in range(months_ahead + 1):
        start, end = month_bounds(moment)
        await connection.execute(text(create_partition(start, end)))
        moment = datetime(end.year, end.month, 1, tzinfo=UTC)
