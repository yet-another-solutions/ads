from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

import msgspec
import structlog
from redis.asyncio import Redis

from ads_policy.config import GovernanceSettings
from ads_policy.contract import IsolationLevel, Run, RunContext, RunState

KEY_PREFIX = "ads:run:"

logger = structlog.get_logger("ads.policy")


def attributes_from_roles(
    roles: Iterable[str], settings: GovernanceSettings | None = None
) -> dict[str, str]:
    """The only place that knows role names, so policy never has to."""
    config = settings or GovernanceSettings()
    held = set(roles)
    return {
        "repo.write": _flag(bool(held & config.write_roles)),
        "agent": _flag(bool(held & config.agent_roles)),
    }


def _flag(value: bool) -> str:
    return "true" if value else "false"


class RunStore(Protocol):
    """Server-side runs: one session yields many, each revocable at once."""

    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel,
        policy_hash: str,
        run_id: str | None = None,
    ) -> Run: ...

    async def get(self, run_id: str) -> Run | None: ...

    async def revoke(self, run_id: str) -> Run: ...

    async def finish(self, run_id: str) -> Run: ...


@dataclass(frozen=True, slots=True, eq=False)
class RedisRunStore:
    """Runs in Redis: the lifetime is the key's, so a forgotten run stops deciding.

    Revocation keeps the remaining lifetime so the audit reads ``run.state`` rather
    than an expired key; once the lifetime is over the record is simply gone.
    """

    redis: Redis
    settings: GovernanceSettings = field(default_factory=GovernanceSettings)

    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel,
        policy_hash: str,
        run_id: str | None = None,
    ) -> Run:
        run = Run(
            id=run_id or uuid.uuid4().hex,
            subject=subject,
            context=context,
            isolation_level=isolation_level,
            policy_hash=policy_hash,
        )
        await self.redis.set(
            _key(run.id), msgspec.json.encode(run), ex=self.settings.run_ttl_seconds
        )
        return run

    async def get(self, run_id: str) -> Run | None:
        raw = await self.redis.get(_key(run_id))
        if raw is None:
            return None
        try:
            return msgspec.json.decode(raw, type=Run)
        except msgspec.DecodeError:
            # A record written by an older shape is a record we cannot act on.
            logger.error("run record unreadable", run_id=run_id)
            return None

    async def revoke(self, run_id: str) -> Run:
        return await self._move(run_id, RunState.REVOKED)

    async def finish(self, run_id: str) -> Run:
        return await self._move(run_id, RunState.FINISHED)

    async def _move(self, run_id: str, state: RunState) -> Run:
        run = await self.get(run_id)
        if run is None:
            raise KeyError(run_id)
        moved = msgspec.structs.replace(run, state=state)
        await self.redis.set(_key(run_id), msgspec.json.encode(moved), keepttl=True)
        return moved


class InMemoryRunStore:
    """Single-process stand-in for tests. Keeps every run it is given, forever."""

    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}

    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel,
        policy_hash: str,
        run_id: str | None = None,
    ) -> Run:
        run = Run(
            id=run_id or uuid.uuid4().hex,
            subject=subject,
            context=context,
            isolation_level=isolation_level,
            policy_hash=policy_hash,
        )
        self._runs[run.id] = run
        return run

    async def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    async def revoke(self, run_id: str) -> Run:
        return await self._move(run_id, RunState.REVOKED)

    async def finish(self, run_id: str) -> Run:
        return await self._move(run_id, RunState.FINISHED)

    async def _move(self, run_id: str, state: RunState) -> Run:
        run = self._runs.get(run_id)
        if run is None:
            raise KeyError(run_id)
        moved = msgspec.structs.replace(run, state=state)
        self._runs[run_id] = moved
        return moved


def _key(run_id: str) -> str:
    return f"{KEY_PREFIX}{run_id}"
