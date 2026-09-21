from __future__ import annotations

from ads_commons.security import SecurityContext
from ads_commons_web.identity import (
    access_token_from_session,
    identity_from_claims,
    identity_from_security_context,
    security_context_from_identity,
)


def test_roles_from_realm_and_client() -> None:
    identity = identity_from_claims(
        {
            "sub": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["user", "offline_access"]},
            "resource_access": {"ads": {"roles": ["user"]}},
        },
        "ads",
    )
    assert identity.sub == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert identity.name == "alice"
    assert "user" in identity.roles
    context = security_context_from_identity(identity)
    assert context.has_role("user")


def test_access_token_from_session() -> None:
    assert access_token_from_session({}) is None
    assert access_token_from_session({"access_token": "  "}) is None
    assert access_token_from_session({"identity": {"sub": "alice"}}) is None
    assert access_token_from_session({"access_token": "user-access-token"}) == "user-access-token"


def test_identity_from_bound_security_context() -> None:
    context = SecurityContext(
        subject="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        name="Alice",
        roles=frozenset({"user"}),
        email="alice@example.com",
        authorized_party="ads",
        access_token="user-access-token",
    )
    identity = identity_from_security_context(context)
    assert identity.sub == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert identity.name == "Alice"
    assert identity.roles == ("user",)
    assert identity.email == "alice@example.com"
    assert identity.azp == "ads"
