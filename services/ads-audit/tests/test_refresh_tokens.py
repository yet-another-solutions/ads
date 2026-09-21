from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from ads_audit.refresh_tokens import SqlRefreshTokenStore
from ads_audit.schema import ensure_schema

pytestmark = pytest.mark.anyio

AUDITOR = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")


async def test_a_refresh_token_is_kept_replaced_and_forgotten_by_sid(postgres_url: str) -> None:
    engine = create_async_engine(postgres_url)
    async with engine.begin() as connection:
        await ensure_schema(connection)
    store = SqlRefreshTokenStore(async_sessionmaker(engine, expire_on_commit=False))
    try:
        assert await store.load("sid-1") is None
        await store.save("sid-1", AUDITOR, "refresh-1")
        await store.save("sid-1", AUDITOR, "refresh-2")
        assert await store.load("sid-1") == "refresh-2"
        await store.delete("sid-1")
        assert await store.load("sid-1") is None
    finally:
        await engine.dispose()
