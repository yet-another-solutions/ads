from __future__ import annotations

import pytest

from ads_commons.security import identity_from_claims, security_context_from_identity

SUBJECT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def test_roles_from_realm_and_client() -> None:
    identity = identity_from_claims(
        {
            "sub": SUBJECT,
            "preferred_username": "alice",
            "email": "alice@example.com",
            "azp": "ads",
            "realm_access": {"roles": ["user", "offline_access"]},
            "resource_access": {"ads": {"roles": ["user"]}},
        },
        "ads",
    )
    assert identity.sub == SUBJECT
    assert identity.name == "alice"
    assert "user" in identity.roles
    context = security_context_from_identity(identity)
    assert context.has_role("user")
    assert context.user_id.hex == "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
    assert identity.azp == "ads"
    assert context.authorized_party == "ads"


def test_missing_sub_is_rejected() -> None:
    with pytest.raises(ValueError, match="sub"):
        identity_from_claims({"name": "alice"}, "ads")


def test_non_uuid_sub_is_rejected() -> None:
    with pytest.raises(ValueError, match="UUID"):
        identity_from_claims({"sub": "alice"}, "ads")
