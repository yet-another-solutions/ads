from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_audit.models import refresh_tokens


@dataclass(frozen=True, slots=True, eq=False)
class SqlRefreshTokenStore:
    sessions: async_sessionmaker[AsyncSession]

    async def load(self, sid: str) -> str | None:
        async with self.sessions() as session:
            statement = select(refresh_tokens.c.refresh_token).where(refresh_tokens.c.sid == sid)
            return (await session.execute(statement)).scalar_one_or_none()

    async def save(self, sid: str, user_id: uuid.UUID, refresh_token: str) -> None:
        statement = insert(refresh_tokens).values(
            sid=sid, user_id=user_id, refresh_token=refresh_token
        )
        async with self.sessions() as session, session.begin():
            await session.execute(
                statement.on_conflict_do_update(
                    index_elements=[refresh_tokens.c.sid],
                    set_={
                        "user_id": user_id,
                        "refresh_token": refresh_token,
                        "updated_at": func.now(),
                    },
                )
            )

    async def delete(self, sid: str) -> None:
        async with self.sessions() as session, session.begin():
            await session.execute(delete(refresh_tokens).where(refresh_tokens.c.sid == sid))
