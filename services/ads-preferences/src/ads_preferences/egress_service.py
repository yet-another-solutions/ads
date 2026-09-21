from __future__ import annotations

from uuid import UUID

import msgspec
from sqlalchemy.orm import Session

from ads_commons.egress import ProjectEgressSettings, ProjectEgressSnapshot
from ads_commons.security import AccessDenied, SecurityContextHolder, ensure_caller, ensure_role
from ads_preferences.config import Settings
from ads_preferences.egress_repository import ProjectEgressRepository
from ads_preferences.exceptions import ModelNotFound
from ads_preferences.models import ProjectEgress


class ProjectEgressService:
    """Ads authorizes project ownership; this service authorizes the operation and caller."""

    def __init__(
        self, session: Session, repository: ProjectEgressRepository, settings: Settings
    ) -> None:
        self._session = session
        self._repository = repository
        self._settings = settings

    def _authorize(self, *, write: bool) -> None:
        identity = SecurityContextHolder.require()
        ensure_caller(identity, "ads")
        if identity.user_id == self._settings.ads_service_subject:
            if write:
                raise AccessDenied("service identity has read-only project egress authority")
        else:
            ensure_role(identity, "user")

    @staticmethod
    def _snapshot(row: ProjectEgress) -> ProjectEgressSnapshot:
        return ProjectEgressSnapshot(
            revision=row.revision,
            settings=msgspec.convert(row.settings, type=ProjectEgressSettings),
        )

    async def get_egress(self, project_id: UUID) -> ProjectEgressSnapshot:
        self._authorize(write=False)
        with self._session.begin():
            row = self._repository.get(project_id)
            if row is None:
                raise ModelNotFound("no such project egress settings")
            return self._snapshot(row)

    async def save_egress(
        self, project_id: UUID, settings: ProjectEgressSettings
    ) -> ProjectEgressSnapshot:
        self._authorize(write=True)
        # Revalidate callers that constructed msgspec structs directly, not through decoding.
        settings = msgspec.json.decode(msgspec.json.encode(settings), type=ProjectEgressSettings)
        payload = msgspec.to_builtins(settings)
        with self._session.begin():
            return self._snapshot(self._repository.save(project_id, payload))

    async def delete_egress(self, project_id: UUID) -> None:
        self._authorize(write=True)
        with self._session.begin():
            self._repository.delete(project_id)
