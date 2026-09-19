from __future__ import annotations

import json
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ads_commons.security import InvalidAccessToken, SecurityContext, ensure_caller
from ads_commons_beans import JwtVerifier, TokenExchangeSettings

MANAGER = "ads-sandbox-manager"
MCP = "ads-sandbox-mcp"
IPC = "ads-sandbox-ipc"


class TokenMinter(Protocol):
    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext: ...


class ClientCredentials:
    """Fresh manager identity for coordination and lifecycle; never a user identity."""

    def __init__(self, settings: TokenExchangeSettings, verifier: JwtVerifier) -> None:
        self.settings = settings
        self.verifier = verifier

    def mint(self) -> str:
        request = Request(
            self.settings.token_endpoint,
            data=urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": self.settings.client_id,
                    "client_secret": self.settings.client_secret,
                }
            ).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(request, context=self.settings.ssl_context, timeout=10) as response:
            payload = json.loads(response.read())
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str):
            raise InvalidAccessToken("client credentials returned no token")
        ensure_caller(self.verifier.authenticate(token), MANAGER)
        return token
