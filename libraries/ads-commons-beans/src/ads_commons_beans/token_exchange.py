from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ads_commons.security import (
    AccessTokenVerifier,
    AuthenticationRequired,
    InvalidAccessToken,
    SecurityContext,
    SecurityContextHolder,
    TokenExchangeError,
)

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


@dataclass(frozen=True)
class TokenExchangeSettings:
    token_endpoint: str
    client_id: str
    client_secret: str
    ssl_context: ssl.SSLContext | None


class TokenExchange:
    """Mint a fresh Standard Token Exchange V2 token. No cache. Does not store tokens."""

    def __init__(
        self,
        settings: TokenExchangeSettings,
        verifier: AccessTokenVerifier,
    ) -> None:
        self._token_endpoint = settings.token_endpoint
        self._client_id = settings.client_id
        self._client_secret = settings.client_secret
        self._verifier = verifier
        self._ssl_context = settings.ssl_context

    def exchange(
        self, audience: str, subject_token: str | None = None, *, scope: str | None = None
    ) -> str:
        """Exchange ``subject_token``, or the bound holder access token when omitted."""
        if not audience.strip():
            raise TokenExchangeError("audience is required")
        if subject_token is None:
            subject_token = SecurityContextHolder.require().access_token
        if not subject_token or not subject_token.strip():
            raise AuthenticationRequired("access token required")
        body = urlencode(
            {
                "grant_type": GRANT_TYPE,
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "subject_token": subject_token,
                "subject_token_type": SUBJECT_TOKEN_TYPE,
                "requested_token_type": REQUESTED_TOKEN_TYPE,
                "audience": audience,
                **({"scope": scope} if scope is not None else {}),
            }
        ).encode()
        request = Request(self._token_endpoint, data=body, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        request.add_header("Accept", "application/json")
        try:
            with urlopen(request, context=self._ssl_context, timeout=10) as response:
                payload: Any = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError) as exc:
            raise TokenExchangeError("token exchange failed") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token.strip():
            raise TokenExchangeError("token exchange returned no access_token")
        return token

    def mint(
        self, audience: str, subject_token: str | None = None, *, scope: str | None = None
    ) -> SecurityContext:
        """Exchange, then wrap the new JWT. Claims come from that token, not the inbound context."""
        token = self.exchange(audience, subject_token, scope=scope)
        try:
            return self._verifier.authenticate(token, audience=audience)
        except InvalidAccessToken as exc:
            raise TokenExchangeError("exchanged token is invalid") from exc
