"""System-supported model types and invoke names, independent of user preferences."""

from __future__ import annotations

import os
from typing import Literal

import msgspec

OpenAiStreamType = Literal["openai-stream"]

# Development stands only. The catalog exists because every listed name has a
# tokenizer baked into ads-context-meter; an unlisted one has none, so its context
# is counted approximately and the pressure built on that count is an estimate.
UNLISTED_MODELS_VARIABLE = "ADS_ALLOW_UNLISTED_MODELS"


class ModelTypeInfo(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    type: OpenAiStreamType
    names: tuple[str, ...]


SUPPORTED_MODEL_TYPES: tuple[ModelTypeInfo, ...] = (
    ModelTypeInfo(type="openai-stream", names=("glm-5.3", "glm-5.2")),
)


def unlisted_models_allowed() -> bool:
    return os.environ.get(UNLISTED_MODELS_VARIABLE) == "1"


def require_supported_model_name(model_type: str, model_name: str) -> None:
    """Reject unknown pairs; never normalize or substitute a provider's invoke name."""
    for supported in SUPPORTED_MODEL_TYPES:
        if supported.type == model_type and model_name in supported.names:
            return
    if model_name and unlisted_models_allowed():
        return
    raise ValueError("unsupported model type/name")
