"""Shared identity, SecurityContextHolder, and JWT verification."""

from ads_commons.security.context import SecurityContext
from ads_commons.security.holder import AuthenticationRequired, SecurityContextHolder
from ads_commons.security.identity import (
    Identity,
    identity_from_claims,
    roles_from_claims,
    security_context_from_identity,
)
from ads_commons.security.jwt import InvalidAccessToken, JwtVerifier, jwks_uri_from_well_known

__all__ = [
    "AuthenticationRequired",
    "Identity",
    "InvalidAccessToken",
    "JwtVerifier",
    "SecurityContext",
    "SecurityContextHolder",
    "identity_from_claims",
    "jwks_uri_from_well_known",
    "roles_from_claims",
    "security_context_from_identity",
]
