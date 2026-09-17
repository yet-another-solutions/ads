from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import msgspec
from redis.asyncio import Redis

BLOCK_PREFIX = "ads:conversation:revoked:"


class ConversationBlock(msgspec.Struct, frozen=True):
    conversation: str
    revoked_at: datetime
    budget: int
    by: str


class ConversationBlocks(Protocol):
    async def block(self, block: ConversationBlock) -> None: ...

    async def is_blocked(self, conversation: str) -> bool: ...


@dataclass(frozen=True, slots=True, eq=False)
class RedisConversationBlocks:
    redis: Redis

    async def block(self, block: ConversationBlock) -> None:
        await self.redis.set(_block_key(block.conversation), msgspec.json.encode(block), nx=True)

    async def is_blocked(self, conversation: str) -> bool:
        if not conversation:
            return False
        return bool(await self.redis.exists(_block_key(conversation)))


class InMemoryConversationBlocks:
    def __init__(self) -> None:
        self._blocks: dict[str, ConversationBlock] = {}

    async def block(self, block: ConversationBlock) -> None:
        self._blocks.setdefault(block.conversation, block)

    async def is_blocked(self, conversation: str) -> bool:
        return bool(conversation) and conversation in self._blocks


def _block_key(conversation: str) -> str:
    return f"{BLOCK_PREFIX}{conversation}"
