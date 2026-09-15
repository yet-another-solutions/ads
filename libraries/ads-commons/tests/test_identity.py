from __future__ import annotations

import pytest

from ads_commons.security import identity_from_claims, security_context_from_identity


def test_roles_from_realm_and_client() -> None:
    identity = identity_from_claims(
        {
            "sub": "u1",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "azp": "ads",
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
    assert identity.azp == "ads"
    assert context.authorized_party == "ads"


def test_missing_sub_is_rejected() -> None:
    with pytest.raises(ValueError, match="sub"):
        identity_from_claims({"name": "alice"}, "ads")
