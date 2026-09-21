from __future__ import annotations

from litestar.middleware.session.client_side import CookieBackendConfig

SESSION_KEY_BYTES = 32
MIN_SESSION_SECRET_BYTES = 16


def cookie_session(secret: str, public_base_url: str) -> CookieBackendConfig:
    if not secret.strip():
        raise RuntimeError("the session secret must be non-empty")
    encoded = secret.encode("utf-8")
    if len(encoded) < MIN_SESSION_SECRET_BYTES:
        raise RuntimeError(f"the session secret must be at least {MIN_SESSION_SECRET_BYTES} bytes")
    return CookieBackendConfig(
        secret=encoded[:SESSION_KEY_BYTES].ljust(SESSION_KEY_BYTES, b"\0"),
        httponly=True,
        secure=public_base_url.startswith("https://"),
        samesite="lax",
        exclude=["/health/live", "/health/ready"],
    )
