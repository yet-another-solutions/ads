from __future__ import annotations

from ads.identity import identity_from_claims, identity_from_session, security_context_from_identity


def test_roles_from_realm_and_client() -> None:
    identity = identity_from_claims(
        {
            "sub": "u1",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "realm_access": {"roles": ["user", "offline_access"]},
            "resource_access": {"ads": {"roles": ["user"]}},
        },
        "ads",
    )
    assert identity.sub == "u1"
    assert identity.name == "alice"
    assert "user" in identity.roles
    context = security_context_from_identity(identity)
    assert context.has_role("user")


def test_session_without_identity() -> None:
    assert identity_from_session({}) is None
    assert identity_from_session({"identity": "bad"}) is None
