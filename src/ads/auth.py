from __future__ import annotations

import secrets
from typing import Any

from dishka.integrations.litestar import FromDishka, inject
from litestar import Controller, Request, get
from litestar.exceptions import NotAuthorizedException
from litestar.response import Redirect
from msgspec import structs

from ads.oidc import OidcClient


class AuthController(Controller):
    path = "/"

    @get("/login")
    @inject
    async def login(
        self, request: Request[Any, Any, Any], oidc: FromDishka[OidcClient]
    ) -> Redirect:
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        request.session["oidc_state"] = state
        request.session["oidc_nonce"] = nonce
        return Redirect(await oidc.authorization_url(state=state, nonce=nonce))

    @get("/auth/callback")
    @inject
    async def callback(
        self, request: Request[Any, Any, Any], oidc: FromDishka[OidcClient]
    ) -> Redirect:
        query = request.query_params
        state = query.get("state")
        code = query.get("code")
        expected_state = request.session.pop("oidc_state", None)
        nonce = request.session.pop("oidc_nonce", None)
        if not state or not code or not expected_state or not nonce or state != expected_state:
            raise NotAuthorizedException(detail="invalid OIDC callback")
        token = await oidc.exchange_code(code)
        id_token = token.get("id_token")
        if not isinstance(id_token, str):
            raise NotAuthorizedException(detail="token response missing id_token")
        identity = oidc.decode_id_token(id_token, nonce=nonce)
        request.session["identity"] = structs.asdict(identity)
        return Redirect("/")

    @get("/logout")
    async def logout(self, request: Request[Any, Any, Any]) -> Redirect:
        request.session.clear()
        return Redirect("/login")
