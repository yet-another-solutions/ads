from __future__ import annotations

import uuid

from dishka.integrations.litestar import FromDishka
from litestar import delete, get

from ads.audit_client import ConversationBlockView
from ads.auditing import AuditingService
from ads_commons_web.authenticated import AuthenticatedController
from ads_commons_web.inject import inject


@inject
class AuditorController(AuthenticatedController):
    """Blocks are the journal's to keep; who may touch them is decided here."""

    path = "/auditor/sessions"
    auditing: FromDishka[AuditingService]

    @get("/{session_id:uuid}/block")
    async def block(self, session_id: uuid.UUID) -> ConversationBlockView:
        return await self.auditing.block_of(session_id)

    @delete("/{session_id:uuid}/block", status_code=200)
    async def lift_block(self, session_id: uuid.UUID) -> ConversationBlockView:
        return await self.auditing.lift_block(session_id)
