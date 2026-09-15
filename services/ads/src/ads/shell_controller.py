"""HTML pages. GET/HEAD only: unauthenticated is a login redirect, never a 401."""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from dishka.integrations.litestar import FromDishka, inject
from litestar import Request, get
from litestar.di import NamedDependency
from litestar.response import Template

from ads.catalog_service import CatalogService
from ads.frontend import FrontendController
from ads.identity import Identity
from ads.project_service import ProjectService
from ads.session_service import SessionService
from ads.views import ModelOption, ModelView, ProjectView, TranscriptView

log = structlog.get_logger("ads.shell")


def initials(name: str) -> str:
    parts = [part for part in name.split() if part]
    if not parts:
        return "AD"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def is_htmx(request: Request[Any, Any, Any]) -> bool:
    return request.headers.get("HX-Request") == "true"


async def model_options(catalog: CatalogService) -> list[ModelOption]:
    """An empty or unreachable catalog keeps the composer inactive, never a 500."""
    try:
        return await catalog.options()
    except Exception as exc:
        log.info("model_options_unavailable", error=str(exc))
        return []


class ShellController(FrontendController):
    path = "/"

    async def _context(
        self,
        identity: Identity,
        projects: ProjectService,
        catalog: CatalogService,
        *,
        q: str | None = None,
        transcript: TranscriptView | None = None,
        project: ProjectView | None = None,
        active_session_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        return {
            "identity": identity,
            "initials": initials(identity.name),
            "projects": await projects.list_tree(q),
            "q": q,
            "transcript": transcript,
            "project": project,
            "active_session_id": active_session_id,
            "active_project_id": project.id if project is not None else None,
            "models": await model_options(catalog),
            "warn": None,
            "selected_model_id": None,
        }

    @get("/")
    @inject
    async def home(
        self,
        request: Request[Any, Any, Any],
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
        catalog: FromDishka[CatalogService],
        q: str | None = None,
    ) -> Template:
        context = await self._context(identity, projects, catalog, q=q)
        if q is not None and is_htmx(request):
            return Template(template_name="fragment_rail.html", context=context)
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/projects/{project_id:uuid}")
    @inject
    async def project_page(
        self,
        request: Request[Any, Any, Any],
        project_id: uuid.UUID,
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
        catalog: FromDishka[CatalogService],
        q: str | None = None,
    ) -> Template:
        project = await projects.get(project_id)
        context = await self._context(identity, projects, catalog, q=q, project=project)
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/projects/{project_id:uuid}/sessions/{session_id:uuid}")
    @inject
    async def session_page(
        self,
        request: Request[Any, Any, Any],
        project_id: uuid.UUID,
        session_id: uuid.UUID,
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
        sessions: FromDishka[SessionService],
        catalog: FromDishka[CatalogService],
        q: str | None = None,
    ) -> Template:
        del project_id
        transcript = await sessions.transcript(session_id)
        context = await self._context(
            identity,
            projects,
            catalog,
            q=q,
            transcript=transcript,
            active_session_id=session_id,
        )
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/dialogs/new-project")
    @inject
    async def new_project_dialog(
        self,
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
    ) -> Template:
        del identity, projects
        return Template(template_name="partials/dialog_new_project.html", context={})

    @get("/dialogs/new-session")
    @inject
    async def new_session_dialog(
        self,
        identity: NamedDependency[Identity],
        projects: FromDishka[ProjectService],
        project_id: uuid.UUID | None = None,
    ) -> Template:
        del identity
        tree = await projects.list_tree(None)
        return Template(
            template_name="partials/dialog_new_session.html",
            context={
                "projects": tree,
                "project_id": project_id,
                "fixed_project": project_id is not None,
            },
        )

    @get("/settings")
    @inject
    async def settings_dialog(
        self,
        identity: NamedDependency[Identity],
        catalog: FromDishka[CatalogService],
        model_id: uuid.UUID | None = None,
    ) -> Template:
        del identity
        models = await _catalog_views(catalog)
        selected = _selected(models, model_id)
        return Template(
            template_name="partials/settings.html",
            context={"models": models, "selected": selected},
        )


async def _catalog_views(catalog: CatalogService) -> list[ModelView]:
    try:
        return await catalog.list_models()
    except Exception as exc:
        log.info("model_list_unavailable", error=str(exc))
        return []


def _selected(models: list[ModelView], model_id: uuid.UUID | None) -> ModelView | None:
    if model_id is None:
        return None
    for model in models:
        if model.id == model_id:
            return model
    return None
