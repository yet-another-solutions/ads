"""Sessions and the send gesture. Mapping only: the service owns the unit of work."""

from __future__ import annotations

import uuid
from typing import Annotated

from dishka.integrations.litestar import FromDishka, inject
from litestar import post
from litestar.di import NamedDependency
from litestar.enums import RequestEncodingType
from litestar.params import Body
from litestar.response import Template

from ads.authenticated import AuthenticatedController
from ads.catalog_service import CatalogService
from ads.identity import Identity
from ads.project_service import ProjectService
from ads.send_service import SendService
from ads.session_service import SessionService
from ads.shell_controller import initials, model_options

Form = Annotated[dict[str, str], Body(media_type=RequestEncodingType.URL_ENCODED)]


def _uuid_or_none(raw: str | None) -> uuid.UUID | None:
    if raw is None or not raw.strip():
        return None
    try:
        return uuid.UUID(raw.strip())
    except ValueError:
        return None


class SessionController(AuthenticatedController):
    path = "/projects"

    @post("/{project_id:uuid}/sessions")
    @inject
    async def create_session(
        self,
        project_id: uuid.UUID,
        data: Form,
        identity: NamedDependency[Identity],
        sessions: FromDishka[SessionService],
        projects: FromDishka[ProjectService],
        catalog: FromDishka[CatalogService],
    ) -> Template:
        created = await sessions.create(
            project_id,
            data.get("name", ""),
            data.get("description", ""),
        )
        transcript = await sessions.transcript(created.id)
        context = {
            "identity": identity,
            "initials": initials(identity.name),
            "projects": await projects.list_tree(None),
            "q": None,
            "transcript": transcript,
            "project": None,
            "active_session_id": created.id,
            "active_project_id": project_id,
            "models": await model_options(catalog),
            "warn": None,
            "selected_model_id": None,
        }
        return Template(
            template_name="fragment_pane.html",
            context=context,
            headers={"HX-Push-Url": f"/projects/{project_id}/sessions/{created.id}"},
        )

    @post("/{project_id:uuid}/sessions/{session_id:uuid}/messages")
    @inject
    async def send_message(
        self,
        project_id: uuid.UUID,
        session_id: uuid.UUID,
        data: Form,
        identity: NamedDependency[Identity],
        send: FromDishka[SendService],
        sessions: FromDishka[SessionService],
        projects: FromDishka[ProjectService],
        catalog: FromDishka[CatalogService],
    ) -> Template:
        del project_id
        model_id = _uuid_or_none(data.get("model_id"))
        await send.send(session_id, data.get("user_input", ""), model_id)
        transcript = await sessions.transcript(session_id)
        context = {
            "identity": identity,
            "initials": initials(identity.name),
            "projects": await projects.list_tree(None),
            "q": None,
            "transcript": transcript,
            "project": None,
            "active_session_id": session_id,
            "active_project_id": transcript.session.project_id,
            "models": await model_options(catalog),
            "warn": None,
            "selected_model_id": model_id,
        }
        return Template(template_name="fragment_pane.html", context=context)
