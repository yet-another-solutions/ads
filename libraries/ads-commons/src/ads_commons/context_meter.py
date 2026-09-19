"""Internal REST contract for estimating ADS context, not provider wire messages."""

from typing import Protocol, runtime_checkable

import msgspec

from ads_commons.engine import HistoryTurn, Reasoning
from ads_commons.model_catalog import require_supported_model_name


class SystemMessage(msgspec.Struct, frozen=True, tag="system", tag_field="type"):
    text: str


class ReasoningMessage(Reasoning, frozen=True, tag="reasoning", tag_field="type"):
    """A tagged version of the existing reasoning primitive for a heterogeneous list."""


ContextPrimitive = HistoryTurn | SystemMessage | ReasoningMessage


class MeterRequest(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    model_name: str
    messages: list[ContextPrimitive]

    def __post_init__(self) -> None:
        require_supported_model_name("openai-stream", self.model_name)


class MeterResponse(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    estimated_tokens: int


@runtime_checkable
class ContextMeterApi(Protocol):
    async def meter(self, body: MeterRequest) -> MeterResponse: ...
