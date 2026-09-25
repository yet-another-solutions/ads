"""TLS-only, owner-verified fresh STE for each supported preferences API call."""

from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
from protected import PreservationError, ProtectedStore

from ads_engine.chat import AdsChatOpenAI


def https(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise PreservationError("explicit verified HTTPS origin required")
    return value.rstrip("/")


class PreferencesModels:
    def __init__(self, store: ProtectedStore, ca_bundle: str | None):
        self.store = store
        context = ssl.create_default_context(cafile=ca_bundle)
        self.client = httpx2.Client(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=20,
        )

    def close(self):
        self.client.close()

    def _request(self, url, *, token=None, method="GET", body=None, form=False):
        kwargs = {}
        if token is not None:
            kwargs["headers"] = {"Authorization": "Bearer " + token}
        if body is not None:
            kwargs["data" if form else "json"] = body
        response = self.client.request(method, url, **kwargs)
        response.raise_for_status()
        if len(response.content) > 8 * 1024 * 1024:
            raise PreservationError("bounded identity/API response required")
        return response.json()

    def _authorization(self, owner):
        if str(UUID(owner)) != owner:
            raise PreservationError("canonical original owner required")
        configured = self.store.read("owner-auth")
        issuer = https(configured["issuer"])
        endpoint = issuer + "/protocol/openid-connect/token"
        if configured["client_id"] != "ads":
            raise PreservationError("restoration must use the supported ADS caller")
        credentials = {
            "client_id": configured["client_id"],
            "client_secret": configured["client_secret"],
        }
        original = configured["owners"][owner]
        refreshed = self._request(
            endpoint,
            method="POST",
            form=True,
            body={
                **credentials,
                "grant_type": "refresh_token",
                "refresh_token": original["refresh_token"],
            },
        )
        if "refresh_token" in refreshed:
            # Persist rotation before the next network operation. If this
            # response is lost the workflow blocks; it never erases the backup.
            configured["owners"][owner]["refresh_token"] = refreshed["refresh_token"]
            self.store.write("owner-auth", configured)
        user = self._request(
            issuer + "/protocol/openid-connect/userinfo",
            token=refreshed["access_token"],
        )
        if user.get("sub") != owner:
            raise PreservationError("delegated restoration owner differs from backup")
        exchanged = self._request(
            endpoint,
            method="POST",
            form=True,
            body={
                **credentials,
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": refreshed["access_token"],
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": "ads-preferences",
            },
        )
        return https(configured["preferences_url"]), exchanged["access_token"]

    def _call(self, owner, path, *, method="GET", payload=None):
        try:
            base, token = self._authorization(owner)
            return self._request(
                base + "/v1/" + path,
                token=token,
                method=method,
                body=payload,
            )
        except Exception:
            raise PreservationError("fresh owner-correct preferences request failed") from None

    def models(self, owner):
        return [self.model(owner, row["id"]) for row in self._call(owner, "models")["models"]]

    def create(self, owner, payload):
        return self._call(owner, "models", method="POST", payload=payload)

    def model(self, owner, model_id):
        return self._call(owner, "models/" + str(UUID(model_id)))

    def invoke(self, owner, model_id):
        try:
            row = self.model(owner, model_id)
            https(row["url"])

            async def call():
                async with asyncio.timeout(60):
                    model = AdsChatOpenAI(
                        model=row["options"]["model-name"],
                        base_url=row["url"],
                        api_key=lambda: row["authentication"]["openai-bearer"]["token"],
                        max_retries=0,
                        max_tokens=32,
                        timeout=45,
                    )
                    await model.ainvoke("Reply OK.")

            # This is a tool-free minimal live validation, not a harness run,
            # dispatcher or replay of discarded session contents.
            asyncio.run(call())
        except Exception:
            raise PreservationError("minimal authenticated provider validation failed") from None
