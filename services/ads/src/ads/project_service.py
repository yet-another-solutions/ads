from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from ads.domain import utc_now
from ads.exceptions import InvalidInput, NotFound
from ads.method_security import require_role
from ads.models import Project
from ads.repository import ProjectRepository, SessionRepository, SessionRunRepository
from ads.views import ProjectView, SessionView
from ads_commons.security import SecurityContextHolder


def _require_text(value: str, field: str) -> str:
    if not value.strip():
        raise InvalidInput(f"{field} must be non-empty")
    return value.strip()


class ProjectService:
    """Owns the project unit of work. Ownership is ``holder.user_id``."""

    def __init__(
        self,
        session: Session,
        projects: ProjectRepository,
        sessions: SessionRepository,
        runs: SessionRunRepository,
    ) -> None:
        self._session = session
        self._projects = projects
        self._sessions = sessions
        self._runs = runs

    @require_role("user")
    async def create(self, name: str, description: str) -> ProjectView:
        user_id = SecurityContextHolder.require().user_id
        clean_name = _require_text(name, "Project name")
        clean_description = _require_text(description, "Project description")
        now = utc_now()
        row = Project(
            id=uuid.uuid4(),
            user_id=user_id,
            name=clean_name,
            description=clean_description,
            created_at=now,
            updated_at=now,
        )
        with self._session.begin():
            stored = self._projects.insert(row)
            return ProjectView(
                id=stored.id,
                name=stored.name,
                description=stored.description,
                sessions=[],
            )

    async def list_tree(self, q: str | None = None) -> list[ProjectView]:
        """Full tree for empty ``q``. Otherwise projects with no session match are omitted."""
        user_id = SecurityContextHolder.require().user_id
        needle = (q or "").strip().lower()
        with self._session.begin():
            tree: list[ProjectView] = []
            for project in self._projects.list_for_user(user_id):
                rows = self._sessions.list_for_project(user_id, project.id)
                if needle:
                    rows = [
                        row
                        for row in rows
                        if needle in row.name.lower() or needle in row.description.lower()
                    ]
                    if not rows:
                        continue
                running = self._runs.in_flight_sessions([row.id for row in rows])
                tree.append(
                    ProjectView(
                        id=project.id,
                        name=project.name,
                        description=project.description,
                        sessions=[
                            SessionView(
                                id=row.id,
                                project_id=row.project_id,
                                name=row.name,
                                description=row.description,
                                running=row.id in running,
                            )
                            for row in rows
                        ],
                    )
                )
            return tree

    async def get(self, project_id: uuid.UUID) -> ProjectView:
        user_id = SecurityContextHolder.require().user_id
        with self._session.begin():
            project = self._projects.get_for_user(user_id, project_id)
            if project is None:
                raise NotFound("no such project")
            return ProjectView(
                id=project.id,
                name=project.name,
                description=project.description,
                sessions=[],
            )
