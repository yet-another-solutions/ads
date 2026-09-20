"""Credential-separated authenticated REST clients. Fresh STE for each hop."""

import asyncio
import ssl
from typing import Protocol

import httpx2
import msgspec

from ads_commons.context_compactor import CompactRequest
from ads_commons.context_meter import MeterRequest, MeterResponse
from ads_commons.engine import Tombstone
from ads_context_runtime.frames import ContextFailure


class Exchange(Protocol):
    def exchange(
        self,
        audience: str,
        subject_token: str | None = None,
        *,
        scope: str | None = None,
    ) -> str: ...


class ContextClients:
    def __init__(
        self,
        exchange: Exchange,
        meter_url: str,
        compactor_url: str,
        verify: ssl.SSLContext,
        subject_token: str | None = None,
    ) -> None:
        self._exchange = exchange
        self._meter_url = meter_url
        self._compactor_url = compactor_url
        self._verify = verify
        self._subject = subject_token

    async def _post(self, url: str, audience: str, body: object) -> bytes:
        try:
            scope = (
                (
                    "ads-engine-context-meter"
                    if audience == "ads-context-meter"
                    else "ads-engine-context-compactor"
                )
                if self._subject is not None
                else None
            )
            token = await asyncio.to_thread(
                self._exchange.exchange,
                audience,
                self._subject,
                scope=scope,
            )
            async with httpx2.AsyncClient(verify=self._verify, timeout=300) as client:
                response = await client.post(
                    url,
                    content=msgspec.json.encode(body),
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                response.raise_for_status()
                return response.content
        except Exception:
            raise ContextFailure("context_service_failed") from None

    async def meter(self, body: MeterRequest) -> MeterResponse:
        return msgspec.json.decode(
            await self._post(self._meter_url, "ads-context-meter", body),
            type=MeterResponse,
        )

    async def compact(self, body: CompactRequest) -> Tombstone:
        return msgspec.json.decode(
            await self._post(self._compactor_url, "ads-context-compactor", body),
            type=Tombstone,
        )
