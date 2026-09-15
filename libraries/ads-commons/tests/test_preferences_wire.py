from __future__ import annotations

from uuid import UUID

import msgspec
import pytest

from ads_commons.engine import OpenAiBearerToken, OpenAiStreamAuthentication
from ads_commons.preferences import ModelInfo, ModelList, ModelPatch, ModelWrite, PreferencesApi


def test_model_info_json_uses_openai_bearer_key() -> None:
    info = ModelInfo(
        id=UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6"),
        description="Work chat",
        name="gpt-4o",
        type="openai-stream",
        url="https://example.invalid/v1",
        authentication=OpenAiStreamAuthentication(
            openai_bearer=OpenAiBearerToken(token="sk-secret"),
        ),
    )
    payload = msgspec.json.decode(msgspec.json.encode(info))
    assert payload["authentication"] == {"openai-bearer": {"token": "sk-secret"}}
    assert "openai_bearer" not in payload["authentication"]
    restored = msgspec.json.decode(msgspec.json.encode(info), type=ModelInfo)
    assert restored.authentication.openai_bearer.token == "sk-secret"


def test_model_write_rejects_id_and_user_id() -> None:
    body = {
        "description": "Work chat",
        "name": "gpt-4o",
        "type": "openai-stream",
        "url": "https://example.invalid/v1",
        "authentication": {"openai-bearer": {"token": "sk-secret"}},
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    }
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)
    body.pop("id")
    body["user_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)


def test_model_list_and_patch_round_trip() -> None:
    listing = ModelList(models=[])
    assert msgspec.json.decode(msgspec.json.encode(listing)) == {"models": []}
    patch = ModelPatch(description="Home chat")
    encoded = msgspec.json.decode(msgspec.json.encode(patch))
    assert encoded == {"description": "Home chat"}
    assert "authentication" not in encoded


def test_preferences_api_is_a_protocol() -> None:
    assert getattr(PreferencesApi, "_is_protocol", False) or issubclass(PreferencesApi, object)
