from __future__ import annotations

import json
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ads_commons.security import InvalidAccessToken, SecurityContext, ensure_caller
from ads_commons_beans import JwtVerifier, TokenExchangeSettings


class TokenMinter(Protocol):
    def mint(self, audience: str, subject_token: str | None = None) -> SecurityContext: ...


class ClientCredentials:
    """Startup identity only; never a substitute for a user STE token."""

    def __init__(self, settings: TokenExchangeSettings, verifier: JwtVerifier) -> None:
        self.settings = settings
        self.verifier = verifier

    def mint(self) -> str:
        body = urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.settings.client_id,
                "client_secret": self.settings.client_secret,
            }
        ).encode()
        request = Request(
            self.settings.token_endpoint,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urlopen(request, context=self.settings.ssl_context, timeout=10) as response:
            payload = json.loads(response.read())
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str):
            raise InvalidAccessToken("client credentials returned no token")
        # UUID sub validation is the common verifier's normal path, including service clients.
        context = self.verifier.authenticate(token, audience="ads-sandbox-manager")
        ensure_caller(context, "ads-sandbox-ipc")
        return token
