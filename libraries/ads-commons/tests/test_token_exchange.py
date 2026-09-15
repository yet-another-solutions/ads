from __future__ import annotations

import json
from typing import Any

import pytest

from ads_commons.security import token_endpoint_from_well_known

TOKEN_URL = "https://kc/realms/ads/protocol/openid-connect/token"
WELL_KNOWN = "https://kc/.well-known/openid-configuration"


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_token_endpoint_from_well_known(monkeypatch: pytest.MonkeyPatch) -> None:
    def _urlopen(url: str, context: Any = None, timeout: int = 10) -> _Response:
        assert url == WELL_KNOWN
        return _Response({"token_endpoint": TOKEN_URL})

    monkeypatch.setattr("ads_commons.security.token_exchange.urlopen", _urlopen)
    assert token_endpoint_from_well_known(WELL_KNOWN) == TOKEN_URL
