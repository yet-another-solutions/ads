from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlsplit

import httpx2
import msgspec

from ads_commons.egress import (
    EgressApplied,
    EgressApply,
    EgressPing,
    EgressStaleResponse,
    ServiceOriginTokens,
)
from ads_sandbox_ipc.egress import StaleRevision


class HttpsEgressTransport:
    """Manager-injected immutable pair URLs. No message can redirect the control client."""

    def __init__(
        self,
        base_url: str,
        relay_urls: tuple[str, str],
        tokens: ServiceOriginTokens,
        ssl_context: ssl.SSLContext | None,
        timeout_seconds: float = 10,
    ) -> None:
        for url in (base_url, *relay_urls):
            parsed = urlsplit(url)
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("paired control URLs must be credential-free HTTPS")
        self.base_url = base_url.rstrip("/")
        self.relay_urls = relay_urls
        self.tokens = tokens
        self.verify = ssl_context if ssl_context is not None else True
        self.timeout_seconds = timeout_seconds

    async def apply(self, body: EgressApply) -> EgressApplied:
        # Mint failures belong to the same two-attempt budget as network/application failures.
        token = await asyncio.to_thread(self.tokens.exchange_service, "ads-sandbox-egress")
        async with httpx2.AsyncClient(timeout=self.timeout_seconds, verify=self.verify) as client:
            response = await client.put(
                self.base_url + "/configuration",
                content=msgspec.json.encode(body),
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            )
        if response.status_code == 409:
            stale = msgspec.json.decode(response.content, type=EgressStaleResponse)
            if (
                stale.error.received_revision == body.snapshot.revision
                and stale.error.applied_revision > body.snapshot.revision
            ):
                raise StaleRevision()
            raise ValueError("invalid stale revision response")
        if response.status_code != 200:
            raise ValueError("egress apply failed")
        return msgspec.json.decode(response.content, type=EgressApplied)

    async def ping(self) -> EgressPing:
        async with httpx2.AsyncClient(timeout=self.timeout_seconds, verify=self.verify) as client:
            response = await client.get(self.base_url + "/ping")
        if response.status_code != 200:
            raise ValueError("egress ping failed")
        return msgspec.json.decode(response.content, type=EgressPing)

    async def relays_healthy(self) -> bool:
        async with httpx2.AsyncClient(timeout=self.timeout_seconds, verify=self.verify) as client:
            replies = await asyncio.gather(*(client.get(url) for url in self.relay_urls))
        return all(reply.status_code == 200 for reply in replies)
