from __future__ import annotations

import secrets
from typing import Any

from dishka.integrations.litestar import FromDishka
from litestar import Controller, Request, get
from litestar.exceptions import NotAuthorizedException
from litestar.response import Redirect

from ads_commons.security import InvalidAccessToken
from ads_commons_web.frontend import pop_return_to
from ads_commons_web.inject import inject
from ads_commons_web.oidc import OidcClient
from ads_commons_web.session_binder import SessionBinder


@inject
class AuthController(Controller):
    path = "/"
    oidc: FromDishka[OidcClient]
    binder: FromDishka[SessionBinder]

    @get("/login")
    async def login(self, request: Request[Any, Any, Any]) -> Redirect:
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        request.session["oidc_state"] = state
        request.session["oidc_nonce"] = nonce
        return Redirect(await self.oidc.authorization_url(state=state, nonce=nonce))

    @get("/auth/callback")
    async def callback(self, request: Request[Any, Any, Any]) -> Redirect:
        query = request.query_params
        state = query.get("state")
        code = query.get("code")
        expected_state = request.session.pop("oidc_state", None)
        nonce = request.session.pop("oidc_nonce", None)
        if not state or not code or not expected_state or not nonce or state != expected_state:
            raise NotAuthorizedException(detail="invalid OIDC callback")
        token = await self.oidc.exchange_code(code)
        id_token = token.get("id_token")
        if not isinstance(id_token, str):
            raise NotAuthorizedException(detail="token response missing id_token")
        try:
            self.oidc.decode_id_token(id_token, nonce=nonce)
        except InvalidAccessToken as exc:
            raise NotAuthorizedException(detail="invalid id_token") from exc
        access_token = token.get("access_token")
        if not isinstance(access_token, str) or not access_token.strip():
            raise NotAuthorizedException(detail="token response missing access_token")
        refresh_token = token.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token.strip():
            raise NotAuthorizedException(detail="token response missing refresh_token")
        try:
            await self.binder.establish(request.session, access_token, refresh_token)
        except InvalidAccessToken as exc:
            raise NotAuthorizedException(detail="invalid access_token") from exc
        return Redirect(pop_return_to(request.session))

    @get("/logout")
    async def logout(self, request: Request[Any, Any, Any]) -> Redirect:
        await self.binder.forget(request.session)
        request.session.clear()
        return Redirect("/login")
