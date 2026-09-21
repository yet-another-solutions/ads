"""Frontend-to-backend. Anonymous is 401; the service may still raise 403."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import msgspec
from dishka.integrations.litestar import FromDishka
from litestar import post
from litestar.di import NamedDependency
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Template

from ads.authenticated import AuthenticatedController
from ads.egress import EgressPublicationFailed
from ads.exceptions import InvalidInput
from ads.identity import Identity
from ads.inject import inject
from ads.project_service import ProjectService
from ads.shell_controller import initials
from ads_commons.egress import ProjectEgressSettings

Form = Annotated[dict[str, str], Body(media_type=RequestEncodingType.URL_ENCODED)]


@inject
class ProjectController(AuthenticatedController):
    path = "/projects"
    projects: FromDishka[ProjectService]

    @post("/{project_id:uuid}/egress-settings", status_code=200)
    async def save_egress(self, project_id: UUID, data: Form) -> Template:
        try:
            settings = msgspec.json.decode(data.get("settings", ""), type=ProjectEgressSettings)
        except msgspec.DecodeError as exc:
            raise InvalidInput(str(exc)) from exc
        publication_failed = False
        try:
            snapshot = await self.projects.save_egress(project_id, settings)
        except EgressPublicationFailed as exc:
            snapshot = exc.snapshot
            publication_failed = True
        return Template(
            template_name="partials/egress_settings.html",
            status_code=503 if publication_failed else 200,
            headers={"X-ADS-Egress-Saved": "true"},
            context={
                "project": await self.projects.get(project_id),
                "snapshot": snapshot,
                "settings_json": msgspec.to_builtins(snapshot.settings),
                "saved": True,
                "publication_failed": publication_failed,
            },
        )

    @post("/")
    async def create_project(
        self,
        data: Form,
        identity: NamedDependency[Identity],
    ) -> Template:
        await self.projects.create(data.get("name", ""), data.get("description", ""))
        return Template(
            template_name="fragment_rail_closed.html",
            context={
                "identity": identity,
                "initials": initials(identity.name),
                "projects": await self.projects.list_tree(None),
                "q": None,
                "active_session_id": None,
            },
        )
