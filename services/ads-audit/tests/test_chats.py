from __future__ import annotations

from typing import Any, cast

import httpx2
import pytest

from ads_audit.chats import ADS_AUDIENCE, ADS_SCOPE, AdsChats, ChatUnavailable
from ads_commons.security import SecurityContext, TokenExchangeError
from ads_commons_beans import TokenExchange
from ads_commons_web.security_holder import SecurityContextHolder

pytestmark = pytest.mark.anyio

CHAT = "3f2b6c1e-0000-4000-8000-000000000001"
AUDITOR = SecurityContext(
    subject="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    name="Ada Auditor",
    roles=frozenset({"auditor"}),
    access_token="auditor-login-token",
)
TRANSCRIPT_AS_ADS_SENDS_IT = {
    "session": {
        "id": CHAT,
        "project_id": "aaaaaaaa-0000-4000-8000-000000000001",
        "name": "Release notes",
        "description": "Draft the notes",
        "running": False,
    },
    "project_name": "ads",
    "turns": [
        {
            "who": "you",
            "at": "2026-09-21T12:00:00Z",
            "parts": [{"kind": "message", "role": "user", "text": "Open an issue", "live": False}],
            "entry_id": "bbbbbbbb-0000-4000-8000-000000000001",
        },
        {
            "who": "agent",
            "at": None,
            "parts": [
                {"kind": "tool_call", "role": None, "text": "create_issue", "name": "create_issue"},
                {"kind": "tool_result", "role": None, "text": "#42", "status": "ok"},
            ],
            "entry_id": None,
        },
    ],
    "run": None,
    "selected_model_id": None,
}


class _Exchange:
    def __init__(self, fails: bool = False) -> None:
        self.asked: list[tuple[str, str | None, str | None]] = []
        self.fails = fails

    def exchange(
        self, audience: str, subject_token: str | None = None, *, scope: str | None = None
    ) -> str:
        self.asked.append((audience, subject_token, scope))
        if self.fails:
            raise TokenExchangeError("token exchange failed")
        return "exchanged-for-ads"


def _chats(handler: Any, exchange: _Exchange | None = None) -> AdsChats:
    return AdsChats(
        "https://ads:8080",
        cast(TokenExchange, exchange or _Exchange()),
        transport=httpx2.MockTransport(handler),
    )


async def test_ads_is_asked_with_the_auditors_token_exchanged_for_ads() -> None:
    seen: list[httpx2.Request] = []
    exchange = _Exchange()

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, json=TRANSCRIPT_AS_ADS_SENDS_IT)

    with SecurityContextHolder.bound(AUDITOR):
        chat = await _chats(handler, exchange).transcript(CHAT)
    assert exchange.asked == [(ADS_AUDIENCE, "auditor-login-token", ADS_SCOPE)]
    assert seen[0].url.path == f"/auditor/sessions/{CHAT}/transcript"
    assert seen[0].headers["authorization"] == "Bearer exchanged-for-ads"
    assert chat is not None
    assert chat.session.name == "Release notes"
    assert [turn.who for turn in chat.turns] == ["you", "agent"]
    assert chat.turns[1].parts[1].text == "#42"


async def test_a_chat_ads_does_not_know_is_none() -> None:
    with SecurityContextHolder.bound(AUDITOR):
        assert await _chats(lambda request: httpx2.Response(404)).transcript(CHAT) is None


@pytest.mark.parametrize("status", [401, 403, 500, 503])
async def test_ads_refusing_or_failing_means_it_is_unavailable(status: int) -> None:
    with SecurityContextHolder.bound(AUDITOR), pytest.raises(ChatUnavailable):
        await _chats(lambda request: httpx2.Response(status)).transcript(CHAT)


async def test_a_failed_exchange_means_ads_is_unavailable() -> None:
    def never(request: httpx2.Request) -> httpx2.Response:
        raise AssertionError("ads must not be asked without a token")

    with SecurityContextHolder.bound(AUDITOR), pytest.raises(ChatUnavailable):
        await _chats(never, _Exchange(fails=True)).transcript(CHAT)
