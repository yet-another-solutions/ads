from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

from dishka.integrations.litestar import FromDishka
from litestar import Request, delete, get
from litestar.di import NamedDependency
from litestar.exceptions import ClientException, NotFoundException
from litestar.response import Redirect, Template

from ads_audit.auditor import AuditorDesk
from ads_audit.repository import Cursor, JournalFilter
from ads_commons_web.authenticated import AuthenticatedController
from ads_commons_web.frontend import FrontendController
from ads_commons_web.identity import Identity, initials
from ads_commons_web.inject import inject
from ads_policy.contract import UNCHECKED_SOURCE_RULE, AuditEvent, Capability, Effect

SECTIONS = (("journal", "Journal"), ("blocks", "Blocks"), ("sources", "Sources"))
MOMENT = "%Y-%m-%d %H:%M:%S"
FORM_MOMENT = "%Y-%m-%dT%H:%M"


@dataclass(frozen=True, slots=True)
class EventRow:
    position: str
    moment: str
    verdict: str
    rule_id: str
    source: str
    tool: str
    capability: str
    resource: str
    subject: str


def moment(value: datetime | None) -> str:
    return "" if value is None else value.astimezone(UTC).strftime(MOMENT)


def verdict(event: AuditEvent) -> str:
    return "unchecked" if event.rule_id == UNCHECKED_SOURCE_RULE else event.effect.value


def event_row(event: AuditEvent) -> EventRow:
    return EventRow(
        position=Cursor(event.recorded_at, event.event_id).encode(),
        moment=moment(event.recorded_at),
        verdict=verdict(event),
        rule_id=event.rule_id,
        source=event.source,
        tool=event.tool,
        capability=event.capability.value if event.capability else "",
        resource=event.resource,
        subject=event.subject,
    )


def is_htmx(request: Request[Any, Any, Any]) -> bool:
    return request.headers.get("HX-Request") == "true"


def _one_of[T](kind: Callable[[str], T], raw: str | None, name: str) -> T | None:
    if not raw:
        return None
    try:
        return kind(raw)
    except ValueError as exc:
        raise ClientException(detail=f"unknown {name}: {raw}") from exc


def _form_moment(raw: str | None, name: str) -> datetime | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ClientException(detail=f"unreadable {name}: {raw}") from exc
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _asked(filter_: JournalFilter) -> dict[str, str]:
    asked = filter_.equalities()
    for bound in ("since", "until"):
        value = getattr(filter_, bound)
        if value is not None:
            asked[bound] = value.astimezone(UTC).strftime(FORM_MOMENT)
    return asked


@inject
class AuditorPages(FrontendController):
    path = "/"
    desk: FromDishka[AuditorDesk]

    def _page(
        self,
        request: Request[Any, Any, Any],
        identity: Identity,
        section: str,
        title: str,
        **context: Any,
    ) -> Template:
        context.update(
            identity=identity,
            initials=initials(identity.name),
            sections=SECTIONS,
            section=section,
            title=title,
            pane=f"partials/{section}.html",
        )
        name = "fragment_pane.html" if is_htmx(request) else "shell.html"
        return Template(template_name=name, context=context)

    @get("/")
    async def home(self) -> Redirect:
        return Redirect("/journal")

    @get("/journal")
    async def journal(
        self,
        request: Request[Any, Any, Any],
        identity: NamedDependency[Identity],
        effect: str | None = None,
        capability: str | None = None,
        rule_id: str = "",
        source: str = "",
        tool: str = "",
        subject: str = "",
        run_id: str = "",
        conversation: str = "",
        since: str | None = None,
        until: str | None = None,
        cursor: str | None = None,
    ) -> Template:
        where = JournalFilter(
            run_id=run_id.strip(),
            subject=subject.strip(),
            conversation=conversation.strip(),
            effect=_one_of(Effect, effect, "effect"),
            capability=_one_of(Capability, capability, "capability"),
            rule_id=rule_id.strip(),
            source=source.strip(),
            tool=tool.strip(),
            since=_form_moment(since, "since"),
            until=_form_moment(until, "until"),
        )
        try:
            page = await self.desk.page(where, cursor)
        except ValueError as exc:
            raise ClientException(detail=f"unreadable cursor: {exc}") from exc
        asked = _asked(where)
        context = {
            "rows": [event_row(event) for event in page.events],
            "next_cursor": page.next_cursor,
            "asked": asked,
            "query": urlencode(asked),
            "effects": [item.value for item in Effect],
            "capabilities": [item.value for item in Capability],
        }
        if cursor and is_htmx(request):
            return Template(template_name="partials/journal_rows.html", context=context)
        return self._page(request, identity, "journal", "Journal", **context)

    @get("/events")
    async def event(
        self, request: Request[Any, Any, Any], identity: NamedDependency[Identity], at: str
    ) -> Template:
        try:
            event = await self.desk.event(at)
        except ValueError as exc:
            raise ClientException(detail=f"unreadable event position: {exc}") from exc
        if event is None:
            raise NotFoundException(detail="no such event")
        return self._page(request, identity, "event", "Event", event=event, row=event_row(event))

    @get("/blocks")
    async def blocks(
        self, request: Request[Any, Any, Any], identity: NamedDependency[Identity]
    ) -> Template:
        blocks = await self.desk.blocks()
        return self._page(request, identity, "blocks", "Blocks", blocks=blocks, moment=moment)

    @get("/sources")
    async def sources(
        self, request: Request[Any, Any, Any], identity: NamedDependency[Identity]
    ) -> Template:
        view = await self.desk.sources()
        return self._page(
            request, identity, "sources", "Sources", view=view, since=moment(view.since)
        )


@inject
class AuditorActions(AuthenticatedController):
    path = "/blocks"
    desk: FromDishka[AuditorDesk]

    @delete("/{conversation:str}", status_code=200)
    async def lift(self, conversation: str) -> Template:
        lifted = await self.desk.lift(conversation)
        if lifted is None:
            raise NotFoundException(detail="no block to lift")
        return Template(
            template_name="partials/block_row.html", context={"block": lifted, "moment": moment}
        )
