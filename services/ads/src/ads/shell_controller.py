"""HTML pages. GET/HEAD only: unauthenticated is a login redirect, never a 401."""

from __future__ import annotations

import uuid
from typing import Any

import structlog
from dishka.integrations.litestar import FromDishka
from litestar import Request, get
from litestar.di import NamedDependency
from litestar.response import Template

from ads.catalog_service import CatalogService
from ads.project_service import ProjectService
from ads.session_service import SessionService
from ads.views import ModelOption, ModelView, ProjectView, TranscriptView
from ads_commons.model_catalog import ModelTypeInfo, unlisted_models_allowed
from ads_commons.security import AccessDenied, AuthenticationRequired
from ads_commons_web.frontend import FrontendController
from ads_commons_web.identity import Identity
from ads_commons_web.inject import inject

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


async def model_options(catalog: CatalogService, identity: Identity) -> list[ModelOption]:
    """An empty or unreachable catalog keeps the composer inactive, never a 500."""
    if "user" not in identity.roles:
        return []
    try:
        return await catalog.options()
    except (AuthenticationRequired, AccessDenied):
        raise
    except Exception as exc:
        log.info("model_options_unavailable", error=str(exc))
        return []


@inject
class ShellController(FrontendController):
    path = "/"
    projects: FromDishka[ProjectService]
    catalog: FromDishka[CatalogService]
    sessions: FromDishka[SessionService]

    async def _context(
        self,
        identity: Identity,
        *,
        q: str | None = None,
        transcript: TranscriptView | None = None,
        project: ProjectView | None = None,
        active_session_id: uuid.UUID | None = None,
    ) -> dict[str, Any]:
        return {
            "identity": identity,
            "initials": initials(identity.name),
            "projects": await self.projects.list_tree(q),
            "q": q,
            "transcript": transcript,
            "project": project,
            "active_session_id": active_session_id,
            "active_project_id": project.id if project is not None else None,
            "models": await model_options(self.catalog, identity),
            "warn": None,
            "selected_model_id": transcript.selected_model_id if transcript else None,
        }

    @get("/")
    async def home(
        self,
        request: Request[Any, Any, Any],
        identity: NamedDependency[Identity],
        q: str | None = None,
    ) -> Template:
        context = await self._context(identity, q=q)
        if q is not None and is_htmx(request):
            return Template(template_name="fragment_rail.html", context=context)
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/projects/{project_id:uuid}")
    async def project_page(
        self,
        request: Request[Any, Any, Any],
        project_id: uuid.UUID,
        identity: NamedDependency[Identity],
        q: str | None = None,
    ) -> Template:
        project = await self.projects.get(project_id)
        context = await self._context(identity, q=q, project=project)
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/projects/{project_id:uuid}/sessions/{session_id:uuid}")
    async def session_page(
        self,
        request: Request[Any, Any, Any],
        project_id: uuid.UUID,
        session_id: uuid.UUID,
        identity: NamedDependency[Identity],
        q: str | None = None,
    ) -> Template:
        del project_id
        transcript = await self.sessions.transcript(session_id)
        context = await self._context(
            identity,
            q=q,
            transcript=transcript,
            active_session_id=session_id,
        )
        if is_htmx(request):
            return Template(template_name="fragment_pane.html", context=context)
        return Template(template_name="shell.html", context=context)

    @get("/dialogs/new-project")
    async def new_project_dialog(
        self,
        identity: NamedDependency[Identity],
    ) -> Template:
        del identity
        return Template(template_name="partials/dialog_new_project.html", context={})

    @get("/dialogs/new-session")
    async def new_session_dialog(
        self,
        identity: NamedDependency[Identity],
        project_id: uuid.UUID | None = None,
    ) -> Template:
        del identity
        tree = await self.projects.list_tree(None)
        return Template(
            template_name="partials/dialog_new_session.html",
            context={
                "projects": tree,
                "project_id": project_id,
                "fixed_project": project_id is not None,
            },
        )

    @get("/settings")
    async def settings_dialog(
        self,
        identity: NamedDependency[Identity],
        model_id: uuid.UUID | None = None,
    ) -> Template:
        del identity
        models = await _catalog_views(self.catalog)
        types = await _model_types(self.catalog)
        selected = _selected(models, model_id)
        return Template(
            template_name="partials/settings.html",
            context={
                "models": models,
                "selected": selected,
                "types": types,
                "unlisted": unlisted_models_allowed(),
            },
        )


async def _catalog_views(catalog: CatalogService) -> list[ModelView]:
    try:
        return await catalog.list_models()
    except (AuthenticationRequired, AccessDenied):
        raise
    except Exception as exc:
        log.info("model_list_unavailable", error=str(exc))
        return []


async def _model_types(catalog: CatalogService) -> list[ModelTypeInfo]:
    try:
        return await catalog.list_model_types()
    except (AuthenticationRequired, AccessDenied):
        raise
    except Exception as exc:
        log.info("model_types_unavailable", error=str(exc))
        return []


def _selected(models: list[ModelView], model_id: uuid.UUID | None) -> ModelView | None:
    if model_id is None:
        return None
    for model in models:
        if model.id == model_id:
            return model
    return None
