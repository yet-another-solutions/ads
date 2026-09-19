"""What an auditor may do with someone else's chat. The role is checked here."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from ads.audit_client import AuditApi, ConversationBlockView
from ads.config import Settings
from ads.exceptions import NotFound
from ads.repository import SessionRepository
from ads_commons.security import check_role


class AuditingService:
    def __init__(
        self,
        session: Session,
        sessions: SessionRepository,
        audit: AuditApi,
        settings: Settings,
    ) -> None:
        self._session = session
        self._sessions = sessions
        self._audit = audit
        self._auditor_role = settings.keycloak_auditor_role

    async def block_of(self, session_id: uuid.UUID) -> ConversationBlockView:
        self._an_auditor_asks(session_id)
        return await self._audit.conversation_block(str(session_id))

    async def lift_block(self, session_id: uuid.UUID) -> ConversationBlockView:
        auditor = self._an_auditor_asks(session_id)
        return await self._audit.lift_conversation_block(str(session_id), auditor)

    def _an_auditor_asks(self, session_id: uuid.UUID) -> str:
        context = check_role(self._auditor_role)
        with self._session.begin():
            if self._sessions.get_any(session_id) is None:
                raise NotFound("no such session")
        return context.subject
