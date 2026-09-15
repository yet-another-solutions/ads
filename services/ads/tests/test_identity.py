from __future__ import annotations

from ads.identity import (
    identity_from_claims,
    identity_from_session,
    security_context_from_identity,
    security_context_from_session,
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


def test_session_without_identity() -> None:
    assert identity_from_session({}) is None
    assert identity_from_session({"identity": "bad"}) is None
    assert security_context_from_session({}) is None


def test_session_context_includes_access_token() -> None:
    session = {
        "identity": {
            "sub": "alice",
            "name": "Alice",
            "roles": ["user"],
            "email": "alice@example.com",
        },
        "access_token": "user-access-token",
    }
    context = security_context_from_session(session)
    assert context is not None
    assert context.subject == "alice"
    assert context.access_token == "user-access-token"
    assert "user-access-token" not in repr(context)
