"""HTTPS client for ads-preferences. S2S only: the browser never sees these payloads."""

from __future__ import annotations

import ssl
from uuid import UUID

import httpx2
import msgspec

from ads.config import Settings
from ads.exceptions import NotFound
from ads.tokens import TokenMinter, ssl_context_for
from ads_commons.preferences import ModelInfo, ModelList, ModelPatch, ModelWrite


class PreferencesUnavailable(Exception):
    """ads-preferences could not be reached or answered with an error."""

    def __init__(self, detail: str = "ads-preferences is unavailable") -> None:
        super().__init__(detail)
        self.detail = detail


class PreferencesClient:
    """Implements ``PreferencesApi``. Each call mints its own STE token."""

    def __init__(
        self,
        settings: Settings,
        tokens: TokenMinter,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._base_url = settings.preferences_base_url.rstrip("/")
        self._audience = settings.preferences_audience
        self._tokens = tokens
        self._ssl_context = ssl_context if ssl_context is not None else ssl_context_for(settings)

    def _verify(self) -> ssl.SSLContext | bool:
        if self._ssl_context is None:
            return True
        return self._ssl_context

    async def _call(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
    ) -> bytes:
        token = self._tokens.exchange(self._audience)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            async with httpx2.AsyncClient(timeout=10.0, verify=self._verify()) as client:
                response = await client.request(
                    method,
                    f"{self._base_url}{path}",
                    content=body,
                    headers=headers,
                )
        except httpx2.HTTPError as exc:
            raise PreferencesUnavailable() from exc
        if response.status_code == 404:
            raise NotFound("no such model")
        if response.status_code >= 400:
            raise PreferencesUnavailable(f"ads-preferences returned {response.status_code}")
        return bytes(response.content)

    async def list_models(self) -> ModelList:
        raw = await self._call("GET", "/v1/models")
        return _decode(raw, ModelList)

    async def get_model(self, model_id: UUID) -> ModelInfo:
        raw = await self._call("GET", f"/v1/models/{model_id}")
        return _decode(raw, ModelInfo)

    async def add_model(self, body: ModelWrite) -> ModelInfo:
        raw = await self._call("POST", "/v1/models", msgspec.json.encode(body))
        return _decode(raw, ModelInfo)

    async def edit_model(self, model_id: UUID, body: ModelPatch) -> ModelInfo:
        raw = await self._call("PATCH", f"/v1/models/{model_id}", msgspec.json.encode(body))
        return _decode(raw, ModelInfo)

    async def delete_model(self, model_id: UUID) -> None:
        await self._call("DELETE", f"/v1/models/{model_id}")


def _decode[T](raw: bytes, expected: type[T]) -> T:
    try:
        return msgspec.json.decode(raw, type=expected)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise PreferencesUnavailable("ads-preferences returned an unexpected body") from exc
