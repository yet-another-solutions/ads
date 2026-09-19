"""System-supported model types and invoke names, independent of user preferences."""

from __future__ import annotations

from typing import Literal

import msgspec

OpenAiStreamType = Literal["openai-stream"]


class ModelTypeInfo(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    type: OpenAiStreamType
    names: tuple[str, ...]


SUPPORTED_MODEL_TYPES: tuple[ModelTypeInfo, ...] = (
    ModelTypeInfo(type="openai-stream", names=("glm-5.3", "glm-5.2")),
)


def require_supported_model_name(model_type: str, model_name: str) -> None:
    """Reject unknown pairs; never normalize or substitute a provider's invoke name."""
    for supported in SUPPORTED_MODEL_TYPES:
        if supported.type == model_type and model_name in supported.names:
            return
    raise ValueError("unsupported model type/name")
