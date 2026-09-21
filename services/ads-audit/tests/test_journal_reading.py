from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ads_audit.models import BLOCKS_TABLE, TABLE
from ads_audit.repository import (
    AuditRepository,
    Cursor,
    InMemoryAuditRepository,
    JournalFilter,
    SourceTraffic,
    SqlAuditRepository,
)
from ads_audit.schema import ensure_schema
from ads_audit.service import AuditService
from ads_policy.contract import UNCHECKED_SOURCE_RULE, AuditEvent, Capability, Effect

pytestmark = pytest.mark.anyio

NOON = datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0)


def _event(
    minute: int,
    *,
    effect: Effect = Effect.ALLOW,
    source: str = "",
    tool: str = "",
    rule_id: str = "fs.read.workdir",
    subject: str = "alice",
) -> AuditEvent:
    return AuditEvent(
        run_id="run-1",
        subject=subject,
        capability=Capability.FS_READ,
        resource=f"/workspace/{minute}",
        effect=effect,
        rule_id=rule_id,
        weight=0 if effect is Effect.ALLOW else 1,
        policy_hash="hash",
        source=source,
        tool=tool,
        event_id=f"event-{minute:03d}",
        recorded_at=NOON + timedelta(minutes=minute),
    )


@pytest.fixture(params=["memory", "postgres"])
async def journal(
    request: pytest.FixtureRequest, anyio_backend: str
) -> AsyncIterator[AuditService]:
    if request.param == "memory":
        yield AuditService(InMemoryAuditRepository())
        return
    engine = create_async_engine(request.getfixturevalue("postgres_url"))
    async with engine.begin() as connection:
        await ensure_schema(connection)
        await connection.execute(text(f"TRUNCATE {TABLE}, {BLOCKS_TABLE}"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    async with sessions() as session, session.begin():
        yield AuditService(SqlAuditRepository(session))
    await engine.dispose()


async def _write(repository: AuditRepository, *events: AuditEvent) -> None:
    for event in events:
        await repository.append(event)


async def test_source_and_tool_come_back_as_they_were_written(journal: AuditService) -> None:
    await _write(journal.repository, _event(1, source="mcp:jira", tool="create_issue"))
    [event] = (await journal.journal(10)).events
    assert (event.source, event.tool) == ("mcp:jira", "create_issue")


async def test_the_journal_narrows_to_what_is_asked(journal: AuditService) -> None:
    await _write(
        journal.repository,
        _event(1, effect=Effect.DENY, source="mcp:jira", tool="create_issue"),
        _event(2, effect=Effect.ALLOW, source="mcp:jira", tool="create_issue"),
        _event(3, effect=Effect.DENY, source="mcp:git", tool="push"),
        _event(4, effect=Effect.DENY, source="mcp:jira", tool="comment", subject="bob"),
    )
    denied_on_jira = JournalFilter(effect=Effect.DENY, source="mcp:jira")
    page = await journal.journal(10, where=denied_on_jira)
    assert [event.event_id for event in page.events] == ["event-004", "event-001"]
    by_bob = JournalFilter(subject="bob", tool="comment")
    assert [e.event_id for e in (await journal.journal(10, where=by_bob)).events] == ["event-004"]


async def test_a_moment_bound_includes_its_start_and_excludes_its_end(
    journal: AuditService,
) -> None:
    await _write(journal.repository, _event(1), _event(2), _event(3))
    window = JournalFilter(since=NOON + timedelta(minutes=1), until=NOON + timedelta(minutes=3))
    page = await journal.journal(10, where=window)
    assert [event.event_id for event in page.events] == ["event-002", "event-001"]


async def test_a_narrowed_journal_pages_like_the_whole_one(journal: AuditService) -> None:
    await _write(
        journal.repository,
        *(_event(minute, effect=Effect.DENY) for minute in range(1, 4)),
        _event(10),
    )
    denials = JournalFilter(effect=Effect.DENY)
    first = await journal.journal(2, where=denials)
    second = await journal.journal(2, first.next_cursor, where=denials)
    assert [e.event_id for e in first.events] == ["event-003", "event-002"]
    assert [e.event_id for e in second.events] == ["event-001"]
    assert second.next_cursor is None


async def test_an_event_is_found_where_its_cursor_points(journal: AuditService) -> None:
    written = _event(5, source="mcp:jira", tool="create_issue")
    await _write(journal.repository, _event(4), written)
    position = Cursor(written.recorded_at, written.event_id).encode()
    found = await journal.event_at(position)
    assert found is not None
    assert (found.event_id, found.source) == (written.event_id, "mcp:jira")
    assert await journal.event_at(Cursor(written.recorded_at, "nothing").encode()) is None


async def test_traffic_is_counted_per_source_within_the_window(journal: AuditService) -> None:
    await _write(
        journal.repository,
        _event(-30, source="mcp:jira"),
        _event(1, source="mcp:jira", rule_id=UNCHECKED_SOURCE_RULE),
        _event(2, source="mcp:jira", rule_id=UNCHECKED_SOURCE_RULE),
        _event(3, source="mcp:git"),
        _event(4, source="mcp:git", effect=Effect.DENY),
        _event(5),
    )
    traffic = await journal.traffic_by_source(since=NOON)
    assert list(traffic) == [
        SourceTraffic(source="mcp:git", allowed=1, denied=1, unchecked=0),
        SourceTraffic(source="mcp:jira", allowed=0, denied=0, unchecked=2),
    ]
