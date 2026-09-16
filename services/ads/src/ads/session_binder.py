"""Derive SecurityContext from the session access token; keep refresh tokens in the DB."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping, MutableMapping
from typing import Any, Protocol, TypeVar

import structlog
from sqlalchemy.orm import Session

from ads.domain import utc_now
from ads.identity import ACCESS_TOKEN_SESSION_KEY, access_token_from_session
from ads.models import OidcRefreshToken
from ads.repository import OidcRefreshTokenRepository
from ads_commons.security import (
    Identity,
    InvalidAccessToken,
    SecurityContext,
    identity_from_claims,
    security_context_from_identity,
)
from ads_commons_beans import JwtVerifier

ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 30

T = TypeVar("T")

log = structlog.get_logger("ads")


class TokenRefresher(Protocol):
    async def refresh_tokens(self, refresh_token: str) -> dict[str, Any]: ...


def _sid(claims: Mapping[str, Any]) -> str | None:
    raw = claims.get("sid")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _seconds_left(claims: Mapping[str, Any]) -> float:
    exp = claims.get("exp")
    if not isinstance(exp, int | float):
        return 0.0
    return float(exp) - time.time()


class SessionBinder:
    """Bind a token-bearing SecurityContext from the cookie access token."""

    def __init__(
        self,
        verifier: JwtVerifier,
        refresher: TokenRefresher,
        session_factory: Callable[[], Session],
        client_id: str,
    ) -> None:
        self._verifier = verifier
        self._refresher = refresher
        self._session_factory = session_factory
        self._client_id = client_id

    def establish(
        self,
        session: MutableMapping[str, Any],
        access_token: str,
        refresh_token: str,
    ) -> None:
        claims = self._verifier.verified_claims(access_token)
        identity = self._identity(claims)
        sid = _sid(claims)
        if sid is None:
            raise InvalidAccessToken("access token missing sid")
        self._store(sid, uuid.UUID(identity.sub), refresh_token)
        self._write_access(session, access_token)

    def forget(self, session: Mapping[str, Any] | None) -> None:
        token = access_token_from_session(session)
        if token is None:
            return
        claims = self._claims(token, verify_exp=False)
        sid = _sid(claims) if claims is not None else None
        if sid is not None:
            self._delete(sid)

    async def bind(self, session: MutableMapping[str, Any]) -> SecurityContext | None:
        access = access_token_from_session(session)
        if access is None:
            return None
        claims, expired = self._verify(access)
        if claims is None:
            return None
        still_valid = not expired and _seconds_left(claims) > 0
        if expired or _seconds_left(claims) <= ACCESS_TOKEN_REFRESH_SKEW_SECONDS:
            rotated = await self._rotate(session, claims)
            if rotated is not None:
                access, claims = rotated
            elif not still_valid:
                return None
        return self._context(access, claims)

    def _verify(self, token: str) -> tuple[dict[str, Any] | None, bool]:
        claims = self._claims(token, verify_exp=True)
        if claims is not None:
            return claims, False
        claims = self._claims(token, verify_exp=False)
        if claims is None:
            return None, False
        return claims, True

    def _claims(self, token: str, *, verify_exp: bool) -> dict[str, Any] | None:
        try:
            return self._verifier.verified_claims(token, verify_exp=verify_exp)
        except InvalidAccessToken:
            return None

    def _identity(self, claims: Mapping[str, Any]) -> Identity:
        try:
            return identity_from_claims(claims, self._client_id)
        except ValueError as exc:
            raise InvalidAccessToken(str(exc)) from exc

    def _context(self, access: str, claims: Mapping[str, Any]) -> SecurityContext | None:
        try:
            identity = self._identity(claims)
        except InvalidAccessToken:
            return None
        context = security_context_from_identity(identity).with_access_token(access)
        if not context.access_token:
            return None
        return context

    async def _rotate(
        self,
        session: MutableMapping[str, Any],
        claims: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any]] | None:
        sid = _sid(claims)
        if sid is None:
            return None
        stored = self._load(sid)
        if stored is None:
            return None
        tokens = await self._refresh_once(sid, stored)
        if tokens is None:
            stored = self._load(sid)
            if stored is None:
                return None
            tokens = await self._refresh_once(sid, stored)
        if tokens is None:
            if _seconds_left(claims) <= 0:
                self._delete(sid)
            return None
        new_access = tokens.get("access_token")
        if not isinstance(new_access, str) or not new_access.strip():
            return None
        new_claims = self._claims(new_access, verify_exp=True)
        if new_claims is None:
            return None
        new_refresh = tokens.get("refresh_token")
        if isinstance(new_refresh, str) and new_refresh.strip():
            try:
                identity = self._identity(new_claims)
            except InvalidAccessToken:
                return None
            self._store(sid, uuid.UUID(identity.sub), new_refresh)
        self._write_access(session, new_access)
        return new_access, new_claims

    async def _refresh_once(self, sid: str, refresh_token: str) -> dict[str, Any] | None:
        try:
            tokens = await self._refresher.refresh_tokens(refresh_token)
        except Exception:
            log.warning("oidc_refresh_failed", sid=sid)
            return None
        if not isinstance(tokens, dict):
            return None
        return tokens

    def _write_access(self, session: MutableMapping[str, Any], access_token: str) -> None:
        session[ACCESS_TOKEN_SESSION_KEY] = access_token
        session.pop("identity", None)
        session.pop("refresh_token", None)

    def _run(self, work: Callable[[OidcRefreshTokenRepository], T]) -> T:
        db_session = self._session_factory()
        try:
            with db_session.begin():
                return work(OidcRefreshTokenRepository(db_session))
        finally:
            db_session.close()

    def _load(self, sid: str) -> str | None:
        def read(repo: OidcRefreshTokenRepository) -> str | None:
            row = repo.get_by_sid(sid)
            if row is None:
                return None
            return row.refresh_token

        return self._run(read)

    def _store(self, sid: str, user_id: uuid.UUID, refresh_token: str) -> None:
        now = utc_now()

        def write(repo: OidcRefreshTokenRepository) -> None:
            repo.put(
                OidcRefreshToken(
                    sid=sid,
                    user_id=user_id,
                    refresh_token=refresh_token,
                    created_at=now,
                    updated_at=now,
                )
            )

        self._run(write)

    def _delete(self, sid: str) -> None:
        self._run(lambda repo: repo.delete_sid(sid))
