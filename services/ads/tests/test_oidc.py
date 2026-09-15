from __future__ import annotations

import asyncio
from typing import cast

import pytest

from ads.config import Settings
from ads.identity import Identity
from ads.oidc import OidcClient
from ads_commons_beans import JwtVerifier


class _RecordingVerifier:
    def __init__(self, identity: Identity) -> None:
        self.identity = identity
        self.calls: list[tuple[str, str | None]] = []

    def decode(
        self,
        token: str,
        *,
        nonce: str | None = None,
        audience: str | None = None,
    ) -> Identity:
        self.calls.append((token, nonce))
        return self.identity


class _MetadataOidcClient(OidcClient):
    async def _get_json(self, url: str) -> dict[str, object]:
        return {"jwks_uri": "https://keycloak.test/jwks"}


def test_decode_id_token_uses_injected_verifier_after_metadata(settings: Settings) -> None:
    identity = Identity(sub="alice", name="Alice", roles=("user",))
    verifier = _RecordingVerifier(identity)
    oidc = _MetadataOidcClient(settings, cast(JwtVerifier, verifier))

    with pytest.raises(RuntimeError, match="OIDC metadata has not been loaded"):
        oidc.decode_id_token("id-token", nonce="expected-nonce")

    asyncio.run(oidc.metadata())

    assert oidc.decode_id_token("id-token", nonce="expected-nonce") is identity
    assert verifier.calls == [("id-token", "expected-nonce")]
