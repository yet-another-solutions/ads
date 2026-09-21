from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
import msgspec
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ads_commons.egress import (
    SandboxProjectBinding,
    ServiceOriginTokens,
    SessionProjectBinding,
)
from ads_commons.security import AccessDenied, SecurityContextHolder, ensure_caller
from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.store import SessionRepository


class AdsSessionProjects:
    """Trusted deployment endpoint; every lookup uses fresh service-origin STE."""

    def __init__(
        self, settings: Settings, tokens: ServiceOriginTokens, context: ssl.SSLContext | None
    ) -> None:
        parsed = urlsplit(settings.ads_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("ADS binding endpoint requires credential-free HTTPS")
        self.settings, self.tokens = settings, tokens
        self.verify = context if context is not None else True

    async def session_project(self, session_id: UUID) -> SessionProjectBinding:
        token = await asyncio.to_thread(self.tokens.exchange_service, "ads")
        async with httpx2.AsyncClient(
            verify=self.verify, timeout=self.settings.control_seconds
        ) as client:
            response = await client.get(
                self.settings.ads_base_url.rstrip("/") + f"/internal/sessions/{session_id}/project",
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise RuntimeError("ADS session project lookup failed")
        binding = msgspec.json.decode(response.content, type=SessionProjectBinding)
        if binding.session_id != session_id:
            raise RuntimeError("ADS session project mismatch")
        return binding


class BindingService:
    """Read-only lifecycle association; no execution or policy assembly surface."""

    def __init__(
        self,
        settings: Settings,
        sessions: async_sessionmaker[AsyncSession],
        repository: SessionRepository,
    ) -> None:
        self.settings, self.sessions, self.repository = settings, sessions, repository

    async def get(self, sandbox_id: UUID) -> SandboxProjectBinding | None:
        context = SecurityContextHolder.require()
        ensure_caller(context, "ads")
        if (
            self.settings.ads_service_subject is None
            or context.user_id != self.settings.ads_service_subject
        ):
            raise AccessDenied("expected ads service identity")
        async with self.sessions.begin() as db:
            row = await self.repository.by_sandbox(db, sandbox_id)
            if row is None:
                return None
            return SandboxProjectBinding(
                row.sandbox_id,
                row.session_id,
                row.project_id,
                row.status in ("pending", "creating", "ready"),
            )
