"""Frontend-to-backend. Anonymous is 401; the service may still raise 403."""

from __future__ import annotations

from typing import Annotated

from dishka.integrations.litestar import FromDishka, inject
from litestar import post
from litestar.di import NamedDependency
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Template

from ads.authenticated import AuthenticatedController
from ads.identity import Identity
from ads.project_service import ProjectService
from ads.shell_controller import initials

Form = Annotated[dict[str, str], Body(media_type=RequestEncodingType.URL_ENCODED)]


class ProjectController(AuthenticatedController):
    path = "/projects"

    @post("/")
    @inject
    async def create_project(
        self,
        data: Form,
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
    ) -> Template:
        await projects.create(data.get("name", ""), data.get("description", ""))
        return Template(
            template_name="fragment_rail_closed.html",
            context={
                "identity": identity,
                "initials": initials(identity.name),
                "projects": await projects.list_tree(None),
                "q": None,
                "active_session_id": None,
            },
        )
