"""In-memory STE subjects for abort. Never persisted; not an STE response cache."""

from __future__ import annotations

import uuid


class AbortSubjects:
    """Last JWT that can be exchanged for an abort header, keyed by session."""

    def __init__(self) -> None:
        self._tokens: dict[uuid.UUID, str] = {}

    def remember(self, session_id: uuid.UUID, token: str | None) -> None:
        if token is None or not token.strip():
            return
        self._tokens[session_id] = token.strip()

    def get(self, session_id: uuid.UUID) -> str | None:
        return self._tokens.get(session_id)

    def forget(self, session_id: uuid.UUID) -> None:
        self._tokens.pop(session_id, None)
