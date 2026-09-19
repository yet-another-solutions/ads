"""Local counting only. Imported and initialized inside a network-denied worker."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from ads_commons.context_meter import MeterRequest, ReasoningMessage, SystemMessage
from ads_commons.engine import AssistantHistoryTurn, ToolCall, ToolResult, UserHistoryTurn
from ads_commons.model_catalog import SUPPORTED_MODEL_TYPES, require_supported_model_name
from ads_context_meter.assets import TOKENIZERS, read_tokenizer
from ads_context_meter.isolation import deny_network

_tokenizers: dict[str, Any] = {}


def initialize(directory: str) -> None:
    # Set before importing LiteLLM, including its lazy modules. Never setdefault:
    # an inherited environment must not re-enable downloads or telemetry.
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    os.environ.pop("CUSTOM_TIKTOKEN_CACHE_DIR", None)
    deny_network()
    expected = {name for model in SUPPORTED_MODEL_TYPES for name in model.names}
    if set(TOKENIZERS) != expected:
        raise RuntimeError("baked tokenizers do not match the ADS model catalog")
    # Verify every asset before importing a library with automatic fallback behavior.
    payloads = {name: read_tokenizer(Path(directory), name) for name in TOKENIZERS}
    import litellm

    litellm.telemetry = False
    litellm.disable_hf_tokenizer_download = True
    litellm.disable_token_counter = False
    # LiteLLM's debug logger prints message bodies. Never enable it in this service.
    logging.getLogger("LiteLLM").disabled = True
    _tokenizers.update({name: litellm.create_tokenizer(text) for name, text in payloads.items()})
    # Exercise lazy imports/default encoding from the wheel while still offline.
    for name in TOKENIZERS:
        count(MeterRequest(name, []))


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def counting_messages(body: MeterRequest) -> list[dict[str, str]]:
    """Keep all submitted content; URLs are text, never fetched as media.

    Tool envelopes deliberately become text so LiteLLM does not drop call names
    and IDs. This is a documented estimate, not a provider's exact chat template.
    Storage/trace metadata is not model context and is excluded.
    """
    messages: list[dict[str, str]] = []
    for item in body.messages:
        if isinstance(item, UserHistoryTurn):
            messages.append({"role": "user", "content": item.text})
        elif isinstance(item, AssistantHistoryTurn):
            messages.append({"role": "assistant", "content": item.text})
        elif isinstance(item, SystemMessage):
            messages.append({"role": "system", "content": item.text})
        elif isinstance(item, ReasoningMessage):
            messages.append({"role": "assistant", "content": f"<think>{item.text}</think>"})
        elif isinstance(item, ToolCall):
            messages.append(
                {
                    "role": "assistant",
                    "content": _json(
                        {
                            "tool_call": {
                                "id": item.id,
                                "name": item.name,
                                "arguments": item.arguments,
                            }
                        }
                    ),
                }
            )
        elif isinstance(item, ToolResult):
            messages.append(
                {
                    "role": "tool",
                    "content": _json(
                        {
                            "tool_call_id": item.tool_call_id,
                            "name": item.name,
                            "status": item.status,
                            "content": item.content,
                        }
                    ),
                }
            )
        else:
            raise ValueError("unsupported context primitive")
    return messages


def count(body: MeterRequest) -> int:
    import litellm

    require_supported_model_name("openai-stream", body.model_name)
    tokenizer = _tokenizers[body.model_name]  # Mandatory, never select/fallback by model name.
    result: int = litellm.token_counter(
        model=body.model_name,
        messages=counting_messages(body),
        custom_tokenizer=tokenizer,
        use_default_image_token_count=True,
    )
    return result
