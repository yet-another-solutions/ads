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
HOLDER_PREFIX = "ads:holder:"

logger = structlog.get_logger("ads.policy")


def attributes_from_roles(
    roles: Iterable[str], settings: GovernanceSettings | None = None
) -> dict[str, str]:
    config = settings or GovernanceSettings()
    held = set(roles)
    return {
        "repo.write": _flag(bool(held & config.write_roles)),
        "agent": _flag(bool(held & config.agent_roles)),
    }


def _flag(value: bool) -> str:
    return "true" if value else "false"


class RunStore(Protocol):
    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel | None,
        policy_hash: str,
        run_id: str | None = None,
        holder: str = "",
        conversation: str = "",
    ) -> Run: ...

    async def get(self, run_id: str) -> Run | None: ...

    async def held_by(self, holder: str) -> list[Run]: ...

    async def touch(self, run: Run) -> None: ...

    async def revoke(self, run_id: str) -> Run: ...

    async def finish(self, run_id: str) -> Run: ...


@dataclass(frozen=True, slots=True, eq=False)
class RedisRunStore:
    redis: Redis
    settings: GovernanceSettings = field(default_factory=GovernanceSettings)

    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel | None,
        policy_hash: str,
        run_id: str | None = None,
        holder: str = "",
        conversation: str = "",
    ) -> Run:
        run = Run(
            id=run_id or uuid.uuid4().hex,
            subject=subject,
            context=context,
            isolation_level=isolation_level,
            policy_hash=policy_hash,
            holder=holder,
            conversation=conversation,
        )
        lifetime = self.settings.run_ttl_seconds
        await self.redis.set(_key(run.id), msgspec.json.encode(run), ex=lifetime)
        if holder:
            await self.redis.sadd(_holder_key(holder), run.id)
            await self.redis.expire(_holder_key(holder), lifetime)
        return run

    async def get(self, run_id: str) -> Run | None:
        raw = await self.redis.get(_key(run_id))
        if raw is None:
            return None
        try:
            return msgspec.json.decode(raw, type=Run)
        except msgspec.DecodeError:
            logger.error("run record unreadable", run_id=run_id)
            return None

    async def held_by(self, holder: str) -> list[Run]:
        runs: list[Run] = []
        for member in await self.redis.smembers(_holder_key(holder)):
            run_id = member.decode() if isinstance(member, bytes) else str(member)
            run = await self.get(run_id)
            if run is None:
                await self.redis.srem(_holder_key(holder), run_id)
                continue
            runs.append(run)
        return runs

    async def touch(self, run: Run) -> None:
        lifetime = self.settings.run_ttl_seconds
        await self.redis.expire(_key(run.id), lifetime)
        if run.holder:
            await self.redis.expire(_holder_key(run.holder), lifetime)

    async def revoke(self, run_id: str) -> Run:
        return await self._change_state_keeping_lifetime(run_id, RunState.REVOKED)

    async def finish(self, run_id: str) -> Run:
        return await self._change_state_keeping_lifetime(run_id, RunState.FINISHED)

    async def _change_state_keeping_lifetime(self, run_id: str, state: RunState) -> Run:
        run = await self.get(run_id)
        if run is None:
            raise KeyError(run_id)
        moved = msgspec.structs.replace(run, state=state)
        await self.redis.set(_key(run_id), msgspec.json.encode(moved), keepttl=True)
        return moved


class InMemoryRunStore:
    def __init__(self) -> None:
        self._runs: dict[str, Run] = {}

    async def start(
        self,
        *,
        subject: str,
        context: RunContext,
        isolation_level: IsolationLevel | None,
        policy_hash: str,
        run_id: str | None = None,
        holder: str = "",
        conversation: str = "",
    ) -> Run:
        run = Run(
            id=run_id or uuid.uuid4().hex,
            subject=subject,
            context=context,
            isolation_level=isolation_level,
            policy_hash=policy_hash,
            holder=holder,
            conversation=conversation,
        )
        self._runs[run.id] = run
        return run

    async def get(self, run_id: str) -> Run | None:
        return self._runs.get(run_id)

    async def held_by(self, holder: str) -> list[Run]:
        return [run for run in self._runs.values() if holder and run.holder == holder]

    async def touch(self, run: Run) -> None:
        return None

    async def revoke(self, run_id: str) -> Run:
        return await self._change_state(run_id, RunState.REVOKED)

    async def finish(self, run_id: str) -> Run:
        return await self._change_state(run_id, RunState.FINISHED)

    async def _change_state(self, run_id: str, state: RunState) -> Run:
        run = self._runs.get(run_id)
        if run is None:
            raise KeyError(run_id)
        moved = msgspec.structs.replace(run, state=state)
        self._runs[run_id] = moved
        return moved


def _key(run_id: str) -> str:
    return f"{KEY_PREFIX}{run_id}"


def _holder_key(holder: str) -> str:
    return f"{HOLDER_PREFIX}{holder}"
