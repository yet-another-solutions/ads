from __future__ import annotations

import json
from typing import Any

import pytest

from ads_commons.security import jwks_uri_from_well_known


def test_jwks_uri_from_well_known(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Response:
        def read(self) -> bytes:
            return json.dumps({"jwks_uri": "https://kc/jwks"}).encode()

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def _urlopen(url: str, context: Any = None, timeout: int = 10) -> _Response:
        assert url == "https://kc/.well-known/openid-configuration"
        return _Response()

    monkeypatch.setattr("ads_commons.security.jwt.urlopen", _urlopen)
    uri = jwks_uri_from_well_known("https://kc/.well-known/openid-configuration")
    assert uri == "https://kc/jwks"
