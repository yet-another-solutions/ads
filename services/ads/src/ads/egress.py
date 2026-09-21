from __future__ import annotations

import asyncio
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID

import httpx2
import msgspec

from ads.config import Settings
from ads.engine_output_service import SessionFactory
from ads.exceptions import NotFound
from ads.repository import SessionRepository
from ads.tokens import TokenMinter, ssl_context_for
from ads_commons.egress import (
    EgressConfigRequest,
    ProjectEgressSnapshot,
    SandboxBindingsApi,
    SandboxProjectBinding,
    SessionProjectBinding,
)
from ads_commons.security import AccessDenied, SecurityContextHolder, ensure_caller


class EgressUpdates(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(self, project_id: UUID, snapshot: ProjectEgressSnapshot) -> None: ...


class StartupPreferences(Protocol):
    async def get_egress_for_startup(self, project_id: UUID) -> ProjectEgressSnapshot: ...


class EgressPublicationFailed(Exception):
    """Persistence succeeded; publication did not. Never report a database rollback."""

    def __init__(self, snapshot: ProjectEgressSnapshot) -> None:
        super().__init__("settings saved, but update publication failed")
        self.snapshot = snapshot


class ManagerBindings:
    def __init__(self, settings: Settings, tokens: TokenMinter) -> None:
        parsed = urlsplit(settings.sandbox_manager_base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("manager binding endpoint requires credential-free HTTPS")
        self.settings, self.tokens = settings, tokens
        self.verify = ssl_context_for(settings) or True

    async def sandbox_binding(self, sandbox_id: UUID) -> SandboxProjectBinding:
        token = await asyncio.to_thread(self.tokens.exchange_service, "ads-sandbox-manager")
        async with httpx2.AsyncClient(verify=self.verify, timeout=10) as client:
            response = await client.get(
                self.settings.sandbox_manager_base_url + f"/v1/sandboxes/{sandbox_id}/binding",
                headers={"Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise RuntimeError("manager binding lookup failed")
        return msgspec.json.decode(response.content, type=SandboxProjectBinding)


class SessionProjectService:
    """ADS owns the association. Narrow manager read needs no browser or model data."""

    def __init__(self, settings: Settings, sessions: SessionFactory) -> None:
        self.settings, self.sessions = settings, sessions

    def project(self, session_id: UUID) -> UUID:
        with self.sessions() as db, db.begin():
            row = SessionRepository(db).get_any(session_id)
            if row is None:
                raise NotFound("session binding not found")
            return row.project_id

    async def for_manager(self, session_id: UUID) -> SessionProjectBinding:
        context = SecurityContextHolder.require()
        ensure_caller(context, "ads-sandbox-manager")
        if (
            self.settings.manager_service_subject is None
            or context.user_id != self.settings.manager_service_subject
        ):
            raise AccessDenied("expected manager service identity")
        return SessionProjectBinding(session_id, self.project(session_id))


class EgressRequestService:
    """A failed identity/binding/read yields no snapshot; no fallback or reconciliation."""

    def __init__(
        self,
        settings: Settings,
        projects: SessionProjectService,
        bindings: SandboxBindingsApi,
        preferences: StartupPreferences,
        updates: EgressUpdates,
    ) -> None:
        self.settings, self.projects = settings, projects
        self.bindings, self.preferences, self.updates = bindings, preferences, updates

    async def request(self, message: EgressConfigRequest) -> None:
        context = SecurityContextHolder.require()
        ensure_caller(context, "ads-sandbox-ipc")
        if (
            self.settings.ipc_service_subject is None
            or context.user_id != self.settings.ipc_service_subject
        ):
            raise AccessDenied("expected IPC service identity")
        async with asyncio.timeout(30):
            binding = await self.bindings.sandbox_binding(message.sandbox_id)
            if (
                not binding.eligible
                or binding.sandbox_id != message.sandbox_id
                or binding.project_id != message.project_id
                or self.projects.project(binding.session_id) != message.project_id
            ):
                raise AccessDenied("sandbox project binding mismatch")
            snapshot = await self.preferences.get_egress_for_startup(message.project_id)
            await self.updates.publish(message.project_id, snapshot)
