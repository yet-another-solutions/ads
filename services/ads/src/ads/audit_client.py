"""HTTPS client for ads-audit. The journal is a service token's business, not a person's."""

from __future__ import annotations

import ssl
from typing import Protocol
from urllib.parse import quote

import httpx2
import msgspec

from ads.config import Settings
from ads.exceptions import NotFound
from ads.tokens import ssl_context_for


class AuditUnavailable(Exception):
    """ads-audit could not be reached or answered with an error."""

    def __init__(self, detail: str = "ads-audit is unavailable") -> None:
        super().__init__(detail)
        self.detail = detail


class ConversationBlockView(msgspec.Struct, frozen=True):
    conversation: str
    budget: int
    blocked_at: str | None = None
    lifted_at: str | None = None
    lifted_by: str = ""

    @property
    def blocked(self) -> bool:
        return self.blocked_at is not None


class AuditApi(Protocol):
    async def conversation_block(self, conversation: str) -> ConversationBlockView: ...

    async def lift_conversation_block(
        self, conversation: str, by: str
    ) -> ConversationBlockView: ...


class AuditClient:
    """What ads asks the journal for. Who may ask is decided in ads, before the call."""

    def __init__(self, settings: Settings, ssl_context: ssl.SSLContext | None = None) -> None:
        self._base_url = settings.audit_url.rstrip("/")
        self._api_token = settings.audit_api_token
        self._ssl_context = ssl_context if ssl_context is not None else ssl_context_for(settings)

    async def conversation_block(self, conversation: str) -> ConversationBlockView:
        return await self._call("GET", f"{self._of(conversation)}/budget")

    async def lift_conversation_block(self, conversation: str, by: str) -> ConversationBlockView:
        return await self._call("DELETE", f"{self._of(conversation)}/block", {"by": by})

    def _of(self, conversation: str) -> str:
        return f"/audit/conversations/{quote(conversation, safe='')}"

    def _verify(self) -> ssl.SSLContext | bool:
        return True if self._ssl_context is None else self._ssl_context

    async def _call(
        self, method: str, path: str, params: dict[str, str] | None = None
    ) -> ConversationBlockView:
        if not self._base_url or not self._api_token:
            raise AuditUnavailable("the journal is not configured")
        headers = {"Authorization": f"Bearer {self._api_token}", "Accept": "application/json"}
        try:
            async with httpx2.AsyncClient(timeout=10.0, verify=self._verify()) as client:
                response = await client.request(
                    method, f"{self._base_url}{path}", params=params, headers=headers
                )
        except httpx2.HTTPError as exc:
            raise AuditUnavailable() from exc
        if response.status_code == 404:
            raise NotFound("this chat carries no block")
        if response.status_code >= 400:
            raise AuditUnavailable(f"ads-audit returned {response.status_code}")
        return _decode(bytes(response.content))


def _decode(raw: bytes) -> ConversationBlockView:
    try:
        return msgspec.json.decode(raw, type=ConversationBlockView)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise AuditUnavailable("unreadable answer from ads-audit") from exc
