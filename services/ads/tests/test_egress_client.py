from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock

import httpx2
import msgspec
import pytest

from ads.config import Settings
from ads.preferences_client import PreferencesClient, PreferencesUnavailable
from ads_commons.egress import ProjectEgressSettings, ProjectEgressSnapshot
from tests.threadline_fakes import FakeTokens


def test_each_preferences_call_exchanges_its_own_token(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_id = uuid.uuid4()
    snapshot = ProjectEgressSnapshot(revision=7, settings=ProjectEgressSettings(rules=()))
    request = AsyncMock(return_value=httpx2.Response(200, content=msgspec.json.encode(snapshot)))
    monkeypatch.setattr(httpx2.AsyncClient, "request", request)
    tokens = FakeTokens()
    client = PreferencesClient(settings, tokens)

    async def calls() -> None:
        assert await client.save_egress(project_id, snapshot.settings) == snapshot
        assert await client.get_egress(project_id) == snapshot
        await client.delete_egress(project_id)

    asyncio.run(calls())
    assert tokens.calls == [(settings.preferences_audience, None)] * 3
    assert [call.args[0] for call in request.call_args_list] == ["PUT", "GET", "DELETE"]
    assert all(
        call.args[1].endswith(f"/v1/projects/{project_id}/egress-settings")
        for call in request.call_args_list
    )


@pytest.mark.parametrize("body", [b"{}", b'{"revision":0,"settings":{"rules":[]}}', b"not-json"])
def test_invalid_persisted_snapshot_is_not_synthesized(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    monkeypatch.setattr(
        httpx2.AsyncClient, "request", AsyncMock(return_value=httpx2.Response(200, content=body))
    )
    with pytest.raises(PreferencesUnavailable):
        asyncio.run(PreferencesClient(settings, FakeTokens()).get_egress(uuid.uuid4()))
