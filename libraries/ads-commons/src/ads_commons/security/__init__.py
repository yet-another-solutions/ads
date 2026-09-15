"""Shared identity, SecurityContextHolder, and JWT verification."""

from ads_commons.security.caller import check_caller, ensure_caller, require_caller
from ads_commons.security.context import SecurityContext
from ads_commons.security.holder import AccessDenied, AuthenticationRequired, SecurityContextHolder
from ads_commons.security.identity import (
    Identity,
    identity_from_claims,
    roles_from_claims,
    security_context_from_identity,
)
from ads_commons.security.jwt import InvalidAccessToken, JwtVerifier, jwks_uri_from_well_known
from ads_commons.security.role import check_role, ensure_role, require_role
from ads_commons.security.token_exchange import (
    TokenExchange,
    TokenExchangeError,
    token_endpoint_from_well_known,
)

__all__ = [
    "AccessDenied",
    "AuthenticationRequired",
    "Identity",
    "InvalidAccessToken",
    "JwtVerifier",
    "SecurityContext",
    "SecurityContextHolder",
    "TokenExchange",
    "TokenExchangeError",
    "check_caller",
    "check_role",
    "ensure_caller",
    "ensure_role",
    "identity_from_claims",
    "jwks_uri_from_well_known",
    "require_caller",
    "require_role",
    "roles_from_claims",
    "security_context_from_identity",
    "token_endpoint_from_well_known",
]
