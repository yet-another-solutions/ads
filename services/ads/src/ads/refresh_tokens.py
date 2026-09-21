from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import TypeVar

from sqlalchemy.orm import Session

from ads.domain import utc_now
from ads.models import OidcRefreshToken
from ads.repository import OidcRefreshTokenRepository

T = TypeVar("T")


class SqlRefreshTokenStore:
    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    async def load(self, sid: str) -> str | None:
        def read(repo: OidcRefreshTokenRepository) -> str | None:
            row = repo.get_by_sid(sid)
            if row is None:
                return None
            return row.refresh_token

        return self._run(read)

    async def save(self, sid: str, user_id: uuid.UUID, refresh_token: str) -> None:
        now = utc_now()

        def write(repo: OidcRefreshTokenRepository) -> None:
            repo.put(
                OidcRefreshToken(
                    sid=sid,
                    user_id=user_id,
                    refresh_token=refresh_token,
                    created_at=now,
                    updated_at=now,
                )
            )

        self._run(write)

    async def delete(self, sid: str) -> None:
        self._run(lambda repo: repo.delete_sid(sid))

    def _run(self, work: Callable[[OidcRefreshTokenRepository], T]) -> T:
        db_session = self._session_factory()
        try:
            with db_session.begin():
                return work(OidcRefreshTokenRepository(db_session))
        finally:
            db_session.close()
