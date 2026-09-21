"""ADS-only REST contract and model-visible memory projection."""

from typing import Literal, Protocol
from uuid import UUID

import msgspec

from ads_commons.engine import HistoryTurn, OpenAiStreamModel, Tombstone

CompactionBoundary = Literal["admission", "continuation", "finish"]


class CompactRequest(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    messages: list[HistoryTurn]
    model: OpenAiStreamModel
    target_percentage: int
    session_id: UUID | None = None
    message_id: UUID | None = None
    compaction_id: UUID | None = None
    boundary: CompactionBoundary = "admission"

    def __post_init__(self) -> None:
        if not 0 < self.target_percentage < 100:
            raise ValueError("target_percentage must be between 1 and 99")


class CompactFailure(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    reason: str
    detail: str = "context request failed"


class ContextCompactorApi(Protocol):
    async def compact(self, body: CompactRequest) -> Tombstone: ...


def memory_text(memory: Tombstone) -> str:
    """Exactly the visible representation. No nested archive or remainder."""
    return msgspec.json.encode(
        {
            "memory_id": str(memory.memory_id),
            "summary": memory.summarization,
            "recall": "memory_recall(memory_id, question) retrieves archived evidence",
        }
    ).decode()


def active_context(memory: Tombstone) -> list[HistoryTurn]:
    return [memory, *memory.remaining_messages]


def recall_source(memory: Tombstone) -> list[HistoryTurn]:
    return ([memory.inner_tombstone] if memory.inner_tombstone else []) + list(memory.messages)
