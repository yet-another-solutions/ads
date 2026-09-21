from __future__ import annotations

import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import quote

import anyio.to_thread
import httpx2
import msgspec

from ads_commons.security import SecurityContextHolder, TokenExchangeError
from ads_commons_beans import TokenExchange

ADS_AUDIENCE = "ads"
ADS_SCOPE = "ads-audit-ads"


class ChatUnavailable(Exception):
    pass


class ChatPart(msgspec.Struct, frozen=True):
    kind: str
    text: str = ""
    role: str | None = None
    live: bool = False
    name: str | None = None
    call_id: str | None = None
    status: str | None = None


class ChatTurn(msgspec.Struct, frozen=True):
    who: str
    at: datetime | None = None
    parts: tuple[ChatPart, ...] = ()
    entry_id: str | None = None


class ChatSession(msgspec.Struct, frozen=True):
    id: str
    name: str
    description: str = ""


class Chat(msgspec.Struct, frozen=True):
    session: ChatSession
    project_name: str = ""
    turns: tuple[ChatTurn, ...] = ()


class Chats(Protocol):
    async def transcript(self, chat: str) -> Chat | None: ...


@dataclass(frozen=True, slots=True, eq=False)
class AdsChats:
    base_url: str
    exchange: TokenExchange
    verify: ssl.SSLContext | bool = True
    transport: httpx2.AsyncBaseTransport | None = None

    async def transcript(self, chat: str) -> Chat | None:
        auditor_token = SecurityContextHolder.require().access_token
        try:
            token = await anyio.to_thread.run_sync(
                lambda: self.exchange.exchange(ADS_AUDIENCE, auditor_token, scope=ADS_SCOPE)
            )
            async with httpx2.AsyncClient(
                timeout=10.0, verify=self.verify, transport=self.transport
            ) as client:
                response = await client.get(
                    f"{self.base_url}/auditor/sessions/{quote(chat, safe='')}/transcript",
                    headers={"authorization": f"Bearer {token}", "accept": "application/json"},
                )
        except (TokenExchangeError, httpx2.HTTPError) as exc:
            raise ChatUnavailable(str(exc)) from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise ChatUnavailable(f"ads answered {response.status_code}")
        try:
            return msgspec.json.decode(bytes(response.content), type=Chat)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise ChatUnavailable("unreadable transcript from ads") from exc


class UnconfiguredChats:
    async def transcript(self, chat: str) -> Chat | None:
        raise ChatUnavailable("ads is not configured")
