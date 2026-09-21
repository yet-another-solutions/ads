from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from ads_preferences.models import ProjectEgress


class ProjectEgressRepository:
    """Caller owns the transaction. One atomic upsert serializes concurrent revisions."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, project_id: UUID) -> ProjectEgress | None:
        return self._session.scalar(
            select(ProjectEgress).where(ProjectEgress.project_id == project_id)
        )

    def save(self, project_id: UUID, settings: dict[str, Any]) -> ProjectEgress:
        dialect = self._session.get_bind().dialect.name
        insert = sqlite_insert if dialect == "sqlite" else pg_insert
        statement = insert(ProjectEgress).values(
            project_id=project_id, revision=1, settings=settings
        )
        returning = statement.on_conflict_do_update(
            index_elements=[ProjectEgress.project_id],
            set_={"revision": ProjectEgress.revision + 1, "settings": statement.excluded.settings},
        ).returning(ProjectEgress)
        return self._session.scalars(returning, execution_options={"populate_existing": True}).one()

    def delete(self, project_id: UUID) -> None:
        self._session.execute(delete(ProjectEgress).where(ProjectEgress.project_id == project_id))
