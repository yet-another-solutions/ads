from __future__ import annotations

import asyncio
import time

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from ads.domain import utc_now
from ads.ioc import session_factory_for
from ads.models import OidcRefreshToken
from ads.refresh_tokens import SqlRefreshTokenStore
from ads_commons.security import InvalidAccessToken
from ads_commons_web.identity import ACCESS_TOKEN_SESSION_KEY
from ads_commons_web.session_binder import ACCESS_TOKEN_REFRESH_SKEW_SECONDS, SessionBinder
from tests.threadline_fakes import (
    USER_ACCESS_TOKEN,
    USER_ID,
    FakeOidcVerifier,
    FakeTokenRefresher,
)


def _binder(
    engine: Engine,
    verifier: FakeOidcVerifier | None = None,
    refresher: FakeTokenRefresher | None = None,
) -> tuple[SessionBinder, FakeOidcVerifier, FakeTokenRefresher]:
    oidc = verifier or FakeOidcVerifier()
    tokens = refresher or FakeTokenRefresher()
    binder = SessionBinder(
        oidc,  # type: ignore[arg-type]
        tokens,
        SqlRefreshTokenStore(session_factory_for(engine)),
        "ads",
    )
    return binder, oidc, tokens


def _row(engine: Engine, sid: str) -> OidcRefreshToken | None:
    with Session(engine) as session:
        return session.get(OidcRefreshToken, sid)


def test_establish_stores_refresh_not_cookie(db_engine: Engine) -> None:
    binder, _, _ = _binder(db_engine)
    session: dict[str, object] = {"identity": {"sub": "stale"}, "refresh_token": "leaked"}
    asyncio.run(binder.establish(session, USER_ACCESS_TOKEN, "refresh-1"))
    assert session[ACCESS_TOKEN_SESSION_KEY] == USER_ACCESS_TOKEN
    assert "identity" not in session
    assert "refresh_token" not in session
    row = _row(db_engine, f"sid-{USER_ID}")
    assert row is not None
    assert row.refresh_token == "refresh-1"
    assert row.user_id == USER_ID


def test_establish_requires_sid(db_engine: Engine) -> None:
    verifier = FakeOidcVerifier()
    verifier.extra_claims["no-sid"] = {
        "sub": str(USER_ID),
        "name": "Alice Operator",
        "email": "alice@example.com",
        "azp": "ads",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
        "iss": "http://keycloak.test/realms/ads",
        "aud": "ads",
        "realm_access": {"roles": ["user"]},
    }
    binder, _, _ = _binder(db_engine, verifier=verifier)
    with pytest.raises(InvalidAccessToken, match="sid"):
        asyncio.run(binder.establish({}, "no-sid", "refresh-1"))
    assert _row(db_engine, f"sid-{USER_ID}") is None


def test_bind_derives_identity_from_token(db_engine: Engine) -> None:
    binder, _, _ = _binder(db_engine)
    session: dict[str, object] = {ACCESS_TOKEN_SESSION_KEY: USER_ACCESS_TOKEN}
    context = asyncio.run(binder.bind(session))
    assert context is not None
    assert context.subject == str(USER_ID)
    assert context.access_token == USER_ACCESS_TOKEN
    assert context.has_role("user")
    assert "identity" not in session


def test_bind_ignores_session_identity(db_engine: Engine) -> None:
    binder, _, _ = _binder(db_engine)
    session: dict[str, object] = {
        ACCESS_TOKEN_SESSION_KEY: USER_ACCESS_TOKEN,
        "identity": {"sub": "someone-else", "roles": ["admin"]},
    }
    context = asyncio.run(binder.bind(session))
    assert context is not None
    assert context.subject == str(USER_ID)
    assert not context.has_role("admin")


def test_near_expiry_refreshes_and_writes_new_access(db_engine: Engine) -> None:
    verifier = FakeOidcVerifier()
    now = int(time.time())
    near = "near-expiry-token"
    rotated = "user-access-token-rotated"
    verifier.extra_claims[near] = {
        "sub": str(USER_ID),
        "name": "Alice Operator",
        "email": "alice@example.com",
        "azp": "ads",
        "sid": f"sid-{USER_ID}",
        "exp": now + ACCESS_TOKEN_REFRESH_SKEW_SECONDS - 5,
        "iat": now,
        "iss": "http://keycloak.test/realms/ads",
        "aud": "ads",
        "realm_access": {"roles": ["user"]},
    }
    verifier.extra_claims[rotated] = {
        "sub": str(USER_ID),
        "name": "Alice Operator",
        "email": "alice@example.com",
        "azp": "ads",
        "sid": f"sid-{USER_ID}",
        "exp": now + 3600,
        "iat": now,
        "iss": "http://keycloak.test/realms/ads",
        "aud": "ads",
        "realm_access": {"roles": ["user"]},
    }
    binder, _, refresher = _binder(db_engine, verifier=verifier)
    session: dict[str, object] = {}
    asyncio.run(binder.establish(session, near, "refresh-1"))
    context = asyncio.run(binder.bind(session))
    assert context is not None
    assert context.access_token == rotated
    assert session[ACCESS_TOKEN_SESSION_KEY] == rotated
    assert refresher.calls == ["refresh-1"]
    row = _row(db_engine, f"sid-{USER_ID}")
    assert row is not None
    assert row.refresh_token == "refresh-2"


def test_refresh_fail_while_valid_keeps_access(db_engine: Engine) -> None:
    verifier = FakeOidcVerifier()
    now = int(time.time())
    near = "near-expiry-token"
    verifier.extra_claims[near] = {
        "sub": str(USER_ID),
        "name": "Alice Operator",
        "email": "alice@example.com",
        "azp": "ads",
        "sid": f"sid-{USER_ID}",
        "exp": now + ACCESS_TOKEN_REFRESH_SKEW_SECONDS - 5,
        "iat": now,
        "iss": "http://keycloak.test/realms/ads",
        "aud": "ads",
        "realm_access": {"roles": ["user"]},
    }
    refresher = FakeTokenRefresher()
    refresher.error = RuntimeError("sso dead")
    binder, _, _ = _binder(db_engine, verifier=verifier, refresher=refresher)
    session: dict[str, object] = {}
    asyncio.run(binder.establish(session, near, "refresh-1"))
    context = asyncio.run(binder.bind(session))
    assert context is not None
    assert context.access_token == near
    assert session[ACCESS_TOKEN_SESSION_KEY] == near
    assert _row(db_engine, f"sid-{USER_ID}") is not None


def test_refresh_fail_when_expired_unbinds_and_deletes_row(db_engine: Engine) -> None:
    verifier = FakeOidcVerifier()
    now = int(time.time())
    expired = "expired-token"
    verifier.extra_claims[expired] = {
        "sub": str(USER_ID),
        "name": "Alice Operator",
        "email": "alice@example.com",
        "azp": "ads",
        "sid": f"sid-{USER_ID}",
        "exp": now - 10,
        "iat": now - 100,
        "iss": "http://keycloak.test/realms/ads",
        "aud": "ads",
        "realm_access": {"roles": ["user"]},
    }
    refresher = FakeTokenRefresher()
    refresher.error = RuntimeError("sso dead")
    binder, _, _ = _binder(db_engine, verifier=verifier, refresher=refresher)
    now_dt = utc_now()
    with Session(db_engine) as db_session:
        with db_session.begin():
            db_session.add(
                OidcRefreshToken(
                    sid=f"sid-{USER_ID}",
                    user_id=USER_ID,
                    refresh_token="refresh-1",
                    created_at=now_dt,
                    updated_at=now_dt,
                )
            )
    session: dict[str, object] = {ACCESS_TOKEN_SESSION_KEY: expired}
    context = asyncio.run(binder.bind(session))
    assert context is None
    assert _row(db_engine, f"sid-{USER_ID}") is None
