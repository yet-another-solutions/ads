from __future__ import annotations

import asyncio
import uuid

from ads_engine.store import ActiveSessionStore


def test_claim_is_unique_per_session() -> None:
    store = ActiveSessionStore("sqlite:///:memory:")
    session_id = uuid.UUID("11111111-1111-1111-1111-111111111111")

    async def _body() -> None:
        assert await store.claim(session_id, uuid.UUID("22222222-2222-2222-2222-222222222222"))
        assert not await store.claim(session_id, uuid.UUID("33333333-3333-3333-3333-333333333333"))
        await store.release(session_id)
        assert await store.claim(session_id, uuid.UUID("44444444-4444-4444-4444-444444444444"))

    asyncio.run(_body())


def test_reset_clears_inflight_rows() -> None:
    store = ActiveSessionStore("sqlite:///:memory:")
    session_id = uuid.UUID("11111111-1111-1111-1111-111111111111")

    async def _body() -> None:
        assert await store.claim(session_id, uuid.UUID("22222222-2222-2222-2222-222222222222"))
        await store.reset()
        assert await store.claim(session_id, uuid.UUID("33333333-3333-3333-3333-333333333333"))

    asyncio.run(_body())
