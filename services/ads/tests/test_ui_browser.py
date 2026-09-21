"""Real Chromium + shipped HTMX/templates; fake engine and in-memory application DB.

No provider calls, lab traffic, or JavaScript reimplementation of browser layout.
Nox installs Chromium; Linux hosts need `playwright install --with-deps chromium`.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from litestar import Litestar
from litestar.testing import TestClient
from playwright.sync_api import Browser, Page, Route, expect, sync_playwright

from ads_commons.engine import AssistantMessage, EngineOutput, Finish, PartialResponse, Reasoning
from tests.threadline_fakes import FakePreferences, login
from tests.threadline_flows import create_project, create_session, send


def test_egress_editor_preserves_omitted_mode_dependent_case_default(
    chat: Chat, preferences: FakePreferences
) -> None:
    import msgspec

    page = chat.page
    page.get_by_role("button", name="Egress settings for").click()
    dialog = page.locator("#egress-settings")
    dialog.get_by_label("Mode", exact=True).select_option("blacklist")
    dialog.get_by_role("button", name="Add rule", exact=True).click()
    rule = dialog.locator("fieldset")
    rule.get_by_label("Domain", exact=True).fill("*.example.com")
    rule.get_by_role("button", name="Add path", exact=True).click()
    expect(rule.get_by_label("Case matching", exact=True)).to_have_value("mode default")
    dialog.get_by_role("button", name="Save settings", exact=True).click()
    expect(page.locator("#egress-settings")).to_contain_text("Revision 2")
    snapshot = next(iter(preferences.egress.values()))
    assert snapshot.settings.mode == "blacklist"
    assert snapshot.settings.rules[0].protocol_settings.paths[0].case_insensitive is msgspec.UNSET


def test_egress_editor_roundtrip_and_rule_order(chat: Chat, preferences: FakePreferences) -> None:
    page = chat.page
    page.get_by_role("button", name="Egress settings for").click()
    dialog = page.locator("#egress-settings")
    expect(dialog).to_be_visible()
    expect(dialog).to_contain_text("Revision 1")
    dialog.get_by_role("button", name="Add rule", exact=True).click()
    first = dialog.locator("fieldset").nth(0)
    first.get_by_label("Domain", exact=True).fill("*.example.com")
    first.get_by_label("Method", exact=True).select_option("GET")
    first.get_by_label("Upgrades", exact=True).select_option("selected")
    first.get_by_label("http/2", exact=True).check()
    first.get_by_role("button", name="Add path", exact=True).click()
    first.get_by_label("Path pattern", exact=True).fill("/api/*")
    first.get_by_label("Case matching", exact=True).select_option("case insensitive")
    dialog.get_by_role("button", name="Add rule", exact=True).click()
    second = dialog.locator("fieldset").nth(1)
    second.get_by_label("Domain", exact=True).fill("second.example.com")
    second.get_by_label("Upgrades", exact=True).select_option("none")
    second.get_by_role("button", name="Move up", exact=True).click()
    dialog.get_by_role("button", name="Save settings", exact=True).click()
    expect(page.locator("#egress-settings")).to_contain_text("Revision 2")
    snapshot = next(iter(preferences.egress.values()))
    assert [rule.domain for rule in snapshot.settings.rules] == [
        "second.example.com",
        "*.example.com",
    ]
    assert snapshot.settings.rules[0].protocol_settings.upgrades == "none"
    assert snapshot.settings.rules[1].protocol_settings.upgrades == ("http/2",)
    assert snapshot.settings.rules[1].protocol_settings.paths[0].case_insensitive is True
    page.locator("#egress-settings").get_by_role("button", name="Close", exact=True).click()
    page.get_by_role("button", name="Egress settings for").click()
    expect(
        page.locator("#egress-settings fieldset").nth(0).get_by_label("Domain", exact=True)
    ).to_have_value("second.example.com")


def emit(client: TestClient, app: Litestar, output: EngineOutput) -> None:
    with client.portal() as portal:
        portal.call(app.state.engine_output_controller.dispatch, output)


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch()
        yield instance
        instance.close()


@dataclass
class Chat:
    page: Page
    client: TestClient
    app: Litestar
    session: uuid.UUID
    path: str
    other_path: str
    model: uuid.UUID
    other_model: uuid.UUID
    order: int = 1
    swaps: int = 0

    def update(self, *, finish: bool = False) -> None:
        emit(
            self.client,
            self.app,
            PartialResponse(
                session_id=self.session,
                order=self.order,
                message=AssistantMessage(text="More streamed output.\n" * 12),
            ),
        )
        self.order += 1
        if finish:
            emit(self.client, self.app, Finish(session_id=self.session, last_order=self.order - 1))
        self.notify()

    def notify(self) -> None:
        self.page.evaluate(
            """session => window.testSocket.dispatchEvent(new MessageEvent("message", {
                data: JSON.stringify({type: "session-updated", session_id: session})
            }))""",
            str(self.session),
        )

    def settled(self) -> None:
        self.swaps += 1
        self.page.wait_for_function("n => window.paneSettles >= n", arg=self.swaps)


@pytest.fixture
def chat(
    browser: Browser, client: TestClient, app: Litestar, preferences: FakePreferences
) -> Iterator[Chat]:
    model, other_model = preferences.seed("First"), preferences.seed("Second")
    login(client)
    project = create_project(client)
    session = create_session(client, project)
    other = create_session(client, project)
    for i in range(16):
        send(client, project, session, f"Question {i}\n" * 5, model.id)
        emit(
            client,
            app,
            PartialResponse(session_id=session, order=0, reasoning=Reasoning(text="Plan.\n" * 8)),
        )
        emit(
            client,
            app,
            PartialResponse(
                session_id=session,
                order=1,
                message=AssistantMessage(text=f"Answer {i}\n" * 12),
            ),
        )
        emit(client, app, Finish(session_id=session, last_order=1))
    send(client, project, session, "Keep streaming", model.id)
    emit(
        client,
        app,
        PartialResponse(session_id=session, order=0, message=AssistantMessage(text="Starting.\n")),
    )
    context = browser.new_context(viewport={"width": 1280, "height": 800})
    page = context.new_page()
    page.add_init_script("""
        window.paneSettles = 0;
        document.addEventListener("htmx:afterSettle", e => {
            if (e.detail.elt.id === "main-pane") window.paneSettles++;
        });
        window.WebSocket = class extends EventTarget {
            static OPEN = 1;
            readyState = 1;
            constructor() {
                super();
                window.testSocket = this;
                setTimeout(() => this.dispatchEvent(new Event("open")), 0);
            }
            send() {}
            close() {}
        };
    """)

    def respond(route: Route) -> None:
        request = route.request
        response = client.request(
            request.method,
            request.url,
            headers=request.headers,
            content=request.post_data_buffer,
        )
        route.fulfill(
            status=response.status_code,
            headers={
                key: value
                for key, value in response.headers.items()
                if key.lower() not in {"content-encoding", "content-length", "set-cookie"}
            },
            body=response.content,
        )

    page.route("http://testserver/**", respond)
    path = f"/projects/{project}/sessions/{session}"
    page.goto("http://testserver" + path)
    page.wait_for_function("window.testSocket !== undefined")
    yield Chat(
        page,
        client,
        app,
        session,
        path,
        f"/projects/{project}/sessions/{other}",
        model.id,
        other_model.id,
    )
    context.close()


def tail_gap(page: Page) -> float:
    return page.locator("#transcript").evaluate(
        "e => e.scrollHeight - e.clientHeight - e.scrollTop"
    )


def to_tail(page: Page) -> None:
    page.locator("#transcript").hover()
    page.mouse.wheel(0, 100000)
    page.wait_for_function(
        """() => {
            const e = document.getElementById("transcript");
            return e.scrollHeight - e.clientHeight - e.scrollTop < 2;
        }"""
    )


@pytest.mark.parametrize("width", [1280, 390])
def test_tail_follows_stream_and_finish_without_losing_model(chat: Chat, width: int) -> None:
    page = chat.page
    page.set_viewport_size({"width": width, "height": 800})
    to_tail(page)
    for finish in (False, False, True):
        chat.update(finish=finish)
        chat.settled()
        assert tail_gap(page) < 2
        expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.model))
    page.reload()
    expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.model))
    assert page.locator("#transcript").evaluate("e => e.clientHeight") > 200


def test_scrolled_reader_keeps_anchor_details_draft_and_model(chat: Chat) -> None:
    page = chat.page
    # Expand historical reasoning using its real control, then scroll into that turn.
    page.locator("details summary").nth(5).click()
    anchor = page.locator(".turn").nth(11).locator("p").last
    anchor.scroll_into_view_if_needed()
    before = anchor.bounding_box()
    assert before is not None
    # aria-disabled guards sending, but these native fields remain editable during a run.
    page.locator('select[name="model_id"]').focus()
    page.locator('select[name="model_id"]').press("End")
    expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.other_model))
    page.locator("#user-input").fill("My next draft", force=True)
    page.locator("#user-input").press("ArrowLeft")
    # Focusing the composer must not change the transcript.
    before = anchor.bounding_box()
    assert before is not None
    for _ in range(3):
        chat.update()
        chat.settled()
        after = anchor.bounding_box()
        assert after is not None
        assert abs(after["y"] - before["y"]) < 2
        assert tail_gap(page) > 100
        expect(page.locator("details").nth(5)).to_have_attribute("open", "")
        expect(page.locator("#user-input")).to_have_value("My next draft")
        expect(page.locator("#user-input")).to_be_focused()
        assert page.locator("#user-input").evaluate("e => e.selectionStart") == 12
        expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.other_model))


def test_delayed_update_uses_scroll_position_at_swap_not_request(chat: Chat) -> None:
    page = chat.page
    pending: list[Route] = []
    page.route("**" + chat.path, lambda route: pending.append(route))
    to_tail(page)
    chat.update()
    page.wait_for_timeout(50)
    assert len(pending) == 1
    page.locator("#transcript").hover()
    page.mouse.wheel(0, -1200)
    page.wait_for_function("document.getElementById('transcript').scrollTop > 0")
    page.wait_for_timeout(100)
    top = page.locator("#transcript").evaluate("e => e.scrollTop")
    pending.pop().fallback()
    chat.settled()
    assert abs(page.locator("#transcript").evaluate("e => e.scrollTop") - top) < 2
    assert tail_gap(page) > 100


def test_live_notifications_coalesce_and_cannot_rewind_navigation(chat: Chat) -> None:
    page = chat.page
    pending: list[Route] = []
    page.route("**" + chat.path, lambda route: pending.append(route))
    chat.update()
    for _ in range(8):
        chat.notify()
    page.wait_for_timeout(100)
    assert len(pending) == 1
    # An in-flight live response from A must not replace B or its composer.
    page.locator(f'a[href="{chat.other_path}"]').click()
    page.wait_for_url("**" + chat.other_path)
    expect(page.locator("#main-pane")).to_have_attribute(
        "data-session-id", chat.other_path.rsplit("/", 1)[1]
    )
    pending.pop().fallback()
    page.wait_for_timeout(100)
    expect(page.locator("#main-pane")).to_have_attribute(
        "data-session-id", chat.other_path.rsplit("/", 1)[1]
    )
    expect(page.locator('select[name="model_id"]')).to_have_value("")
    assert len(pending) == 0


def test_send_clears_submitted_draft_and_retains_selection(chat: Chat) -> None:
    page = chat.page
    chat.update(finish=True)
    chat.settled()
    to_tail(page)
    page.locator('select[name="model_id"]').select_option(str(chat.other_model))
    page.locator("#user-input").fill("Send this once")
    page.locator("#user-input").press("Enter")
    chat.settled()
    expect(page.locator("#user-input")).to_have_value("")
    expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.other_model))
    assert tail_gap(page) < 2
    page.reload()
    expect(page.locator('select[name="model_id"]')).to_have_value(str(chat.other_model))


def test_notifications_during_refresh_get_one_catch_up_refresh(chat: Chat) -> None:
    page = chat.page
    pending: list[Route] = []
    page.route("**" + chat.path, lambda route: pending.append(route))
    to_tail(page)
    chat.update()
    for _ in range(8):
        chat.notify()
    page.wait_for_timeout(100)
    assert len(pending) == 1
    pending.pop().fallback()
    chat.settled()
    page.wait_for_timeout(100)
    assert len(pending) == 1
    pending.pop().fallback()
    chat.settled()
    page.wait_for_timeout(100)
    assert pending == []
    assert tail_gap(page) < 2


def test_draft_typed_while_send_waits_survives_response(chat: Chat) -> None:
    page = chat.page
    chat.update(finish=True)
    chat.settled()
    pending: list[Route] = []
    page.route("**" + chat.path + "/messages", lambda route: pending.append(route))
    page.locator("#user-input").fill("Send this")
    page.locator("#user-input").press("Enter")
    page.wait_for_timeout(50)
    assert len(pending) == 1
    page.locator("#user-input").fill("Next draft typed during request")
    pending.pop().fallback()
    chat.settled()
    expect(page.locator("#user-input")).to_have_value("Next draft typed during request")


def test_scrolled_reader_stays_put_when_runbar_disappears(chat: Chat) -> None:
    page = chat.page
    anchor = page.locator(".turn").nth(11).locator("p").last
    anchor.scroll_into_view_if_needed()
    before = anchor.bounding_box()
    assert before is not None
    chat.update(finish=True)
    chat.settled()
    after = anchor.bounding_box()
    assert after is not None
    assert abs(after["y"] - before["y"]) < 2
    assert tail_gap(page) > 100
