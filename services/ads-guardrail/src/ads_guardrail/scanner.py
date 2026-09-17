from __future__ import annotations

import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

import aiohttp
import msgspec

from ads_commons.injection_scanner import SCAN_PATH, ScanRequest, ScanResponse


@dataclass(frozen=True, slots=True)
class InjectionScan:
    found: bool
    highest_score: float
    unavailable_reason: str = ""

    @staticmethod
    def of(response: ScanResponse) -> InjectionScan:
        return InjectionScan(response.injection_found, response.highest_score)

    @staticmethod
    def unavailable(reason: str) -> InjectionScan:
        return InjectionScan(found=False, highest_score=0.0, unavailable_reason=reason)


class InjectionScanner(Protocol):
    async def scan(self, texts: Sequence[str]) -> InjectionScan: ...

    async def close(self) -> None: ...


class HttpInjectionScanner:
    def __init__(
        self, base_url: str, api_token: str, tls: ssl.SSLContext | bool, timeout_seconds: float
    ) -> None:
        self._url = f"{base_url.rstrip('/')}{SCAN_PATH}"
        self._session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=tls),
            timeout=aiohttp.ClientTimeout(total=timeout_seconds),
            headers={"authorization": f"Bearer {api_token}"},
        )

    async def scan(self, texts: Sequence[str]) -> InjectionScan:
        body = msgspec.json.encode(ScanRequest(texts=list(texts)))
        try:
            async with self._session.post(
                self._url, data=body, headers={"content-type": "application/json"}
            ) as response:
                if response.status != 200:
                    return InjectionScan.unavailable(f"scanner answered {response.status}")
                payload = await response.read()
        except (aiohttp.ClientError, TimeoutError) as exc:
            return InjectionScan.unavailable(f"scanner unreachable: {exc}")
        try:
            return InjectionScan.of(msgspec.json.decode(payload, type=ScanResponse))
        except msgspec.DecodeError as exc:
            return InjectionScan.unavailable(f"unreadable scanner answer: {exc}")

    async def close(self) -> None:
        await self._session.close()


class UnconfiguredInjectionScanner:
    async def scan(self, texts: Sequence[str]) -> InjectionScan:
        return InjectionScan.unavailable("no injection scanner is configured")

    async def close(self) -> None:
        return None
