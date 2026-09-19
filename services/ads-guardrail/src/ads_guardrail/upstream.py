"""Tokens for the servers behind the proxy. A caller's own token never goes upstream."""

from __future__ import annotations

import hashlib
import threading
import time

import jwt

from ads_commons.security import TokenExchangeError
from ads_commons_beans import TokenExchange


class UpstreamTokens:
    """Exchange the caller's token for one the upstream server asks for, and reuse it."""

    def __init__(self, exchange: TokenExchange, skew_seconds: float = 30.0) -> None:
        self._exchange = exchange
        self._skew = skew_seconds
        self._minted: dict[tuple[str, str], tuple[str, float]] = {}
        self._lock = threading.Lock()

    def bearer_for(self, audience: str, subject_token: str) -> str:
        key = (audience, hashlib.sha256(subject_token.encode("utf-8")).hexdigest())
        now = time.time()
        with self._lock:
            held = self._minted.get(key)
            if held is not None and held[1] > now:
                return held[0]
        context = self._exchange.mint(audience, subject_token)
        minted = context.access_token
        if not minted:
            raise TokenExchangeError(f"no token was minted for {audience!r}")
        with self._lock:
            self._minted = {
                held_key: held
                for held_key, held in self._minted.items()
                if held[1] > now and held_key != key
            }
            self._minted[key] = (minted, _expires_at(minted) - self._skew)
        return minted


def _expires_at(token: str) -> float:
    """The minted token is already verified; this only reads when to stop reusing it."""
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError:
        return 0.0
    expiry = claims.get("exp")
    return float(expiry) if isinstance(expiry, int | float) else 0.0
