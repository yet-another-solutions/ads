from __future__ import annotations

from uuid import UUID

import msgspec
import pytest

from ads_commons.engine import OpenAiBearerToken, OpenAiStreamAuthentication, OpenAiStreamOptions
from ads_commons.model_catalog import SUPPORTED_MODEL_TYPES
from ads_commons.preferences import (
    ModelInfo,
    ModelList,
    ModelPatch,
    ModelTypeList,
    ModelWrite,
    PreferencesApi,
)


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
        options=OpenAiStreamOptions(model_name="glm-5.3", max_context_tokens=32768),
    )
    payload = msgspec.json.decode(msgspec.json.encode(info))
    assert payload["authentication"] == {"openai-bearer": {"token": "sk-secret"}}
    assert "openai_bearer" not in payload["authentication"]
    assert payload["options"] == {"model-name": "glm-5.3", "max_context_tokens": 32768}
    assert "model_name" not in payload["options"]
    restored = msgspec.json.decode(msgspec.json.encode(info), type=ModelInfo)
    assert restored.authentication.openai_bearer.token == "sk-secret"
    assert restored.options.model_name == "glm-5.3"


def test_model_write_rejects_id_and_user_id() -> None:
    body = {
        "description": "Work chat",
        "name": "gpt-4o",
        "type": "openai-stream",
        "url": "https://example.invalid/v1",
        "authentication": {"openai-bearer": {"token": "sk-secret"}},
        "options": {"model-name": "glm-5.3", "max_context_tokens": 32768},
        "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    }
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)
    body.pop("id")
    body["user_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)


def test_model_write_requires_openai_stream_options() -> None:
    body = {
        "description": "Work chat",
        "name": "work",
        "type": "openai-stream",
        "url": "https://example.invalid/v1",
        "authentication": {"openai-bearer": {"token": "sk-secret"}},
    }
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)
    body["options"] = {"model-name": "glm-5.3", "max_context_tokens": 32768, "temperature": 0.2}
    with pytest.raises(msgspec.ValidationError):
        msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)
    body["options"] = {"model-name": "glm-5.3", "max_context_tokens": 32768}
    decoded = msgspec.json.decode(msgspec.json.encode(body), type=ModelWrite)
    assert decoded.options.model_name == "glm-5.3"


def test_model_list_and_patch_round_trip() -> None:
    listing = ModelList(models=[])
    assert msgspec.json.decode(msgspec.json.encode(listing)) == {"models": []}
    patch = ModelPatch(description="Home chat")
    encoded = msgspec.json.decode(msgspec.json.encode(patch))
    assert encoded == {"description": "Home chat"}
    assert "authentication" not in encoded


def test_preferences_api_is_a_protocol() -> None:
    assert getattr(PreferencesApi, "_is_protocol", False) or issubclass(PreferencesApi, object)


def test_model_type_list_round_trip() -> None:
    listing = ModelTypeList(types=list(SUPPORTED_MODEL_TYPES))
    assert msgspec.json.decode(msgspec.json.encode(listing)) == {
        "types": [{"type": "openai-stream", "names": ["glm-5.3", "glm-5.2"]}]
    }
    assert msgspec.json.decode(msgspec.json.encode(listing), type=ModelTypeList) == listing


@pytest.mark.parametrize("name", ["glm-5.3", "glm-5.2"])
def test_supported_invoke_names_round_trip(name: str) -> None:
    options = OpenAiStreamOptions(model_name=name, max_context_tokens=32768)
    assert (
        msgspec.json.decode(msgspec.json.encode(options), type=OpenAiStreamOptions).model_name
        == name
    )


@pytest.mark.parametrize("name", ["gpt-4o", "GLM-5.3", "", " glm-5.3 "])
def test_unknown_invoke_names_rejected_by_constructor_and_wire(name: str) -> None:
    with pytest.raises(ValueError, match="unsupported model type/name"):
        OpenAiStreamOptions(model_name=name, max_context_tokens=32768)
    with pytest.raises(msgspec.ValidationError, match="unsupported model type/name"):
        msgspec.json.decode(
            msgspec.json.encode({"model-name": name, "max_context_tokens": 32768}),
            type=OpenAiStreamOptions,
        )
