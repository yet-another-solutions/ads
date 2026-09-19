from __future__ import annotations

from litestar import Litestar, get
from litestar.middleware import DefineMiddleware
from litestar.params import FromQuery
from litestar.testing import TestClient

from ads.app import build_session_config
from ads.authenticated import AuthenticatedController
from ads.config import Settings
from ads.governance.enforcement import Enforcer, require_permission
from ads.governance.middleware import PolicyEnforcementMiddleware
from ads.security_middleware import SecurityContextMiddleware
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.config import DENIED_MESSAGE
from ads_policy.contract import Capability, IsolationLevel
from ads_policy.service import PolicyService
from tests.policy import ATTRIBUTES, DirectPolicyClient, journalled, run_request
from tests.threadline_fakes import USER_ID, attach_fake_session_binder, login


class _AgentTools:
    @require_permission(Capability.FS_READ, resource_arg="path")
    def read_file(self, path: str) -> str:
        return f"contents of {path}"


class _ToolController(AuthenticatedController):
    path = "/tools"

    @get("/file")
    async def read_file(self, path: FromQuery[str]) -> dict[str, str]:
        return {"body": _AgentTools().read_file(path)}


def _app(
    settings: Settings, policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> Litestar:
    # The person is whoever the session's access token names, so the run is theirs.
    run = policy_client.start_run(run_request(IsolationLevel.CONTAINER, subject=str(USER_ID)))
    enforcer = Enforcer(client=policy_client, run=run, audit=audit, attributes=ATTRIBUTES)
    session_config = build_session_config(settings)
    app = Litestar(
        route_handlers=[_ToolController],
        middleware=[
            session_config.middleware,
            SecurityContextMiddleware,
            DefineMiddleware(PolicyEnforcementMiddleware, provider=lambda scope: enforcer),
        ],
    )
    attach_fake_session_binder(app)
    return app


def test_unauthenticated_tool_call_is_unauthorized(
    settings: Settings, policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    session_config = build_session_config(settings)
    app = _app(settings, policy_client, audit)
    with TestClient(app=app, session_config=session_config) as client:
        response = client.get("/tools/file", params={"path": "/workspace/src/app.py"})
        assert response.status_code == 401
    assert audit.pending == ()


def test_permitted_tool_call_returns_the_body(
    settings: Settings,
    policy_client: DirectPolicyClient,
    audit: BufferedAuditSink,
    service: PolicyService,
    service_journal: CollectingAuditSink,
) -> None:
    session_config = build_session_config(settings)
    app = _app(settings, policy_client, audit)
    with TestClient(app=app, session_config=session_config) as client:
        login(client)
        response = client.get("/tools/file", params={"path": "/workspace/src/app.py"})
        assert response.status_code == 200
        assert response.json() == {"body": "contents of /workspace/src/app.py"}
    assert audit.pending == ()
    journalled(service)
    assert service_journal.events()[-1].resource == "/workspace/src/app.py"


def test_denied_tool_call_is_forbidden_without_a_map_of_the_perimeter(
    settings: Settings, policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    session_config = build_session_config(settings)
    app = _app(settings, policy_client, audit)
    with TestClient(app=app, session_config=session_config) as client:
        login(client)
        response = client.get("/tools/file", params={"path": "/home/dev/other/.env"})
    assert response.status_code == 403
    assert DENIED_MESSAGE in response.text
    assert Capability.FS_READ.value not in response.text
    assert IsolationLevel.VM.value not in response.text


def test_the_enforcer_does_not_leak_between_requests(
    settings: Settings, policy_client: DirectPolicyClient, audit: BufferedAuditSink
) -> None:
    session_config = build_session_config(settings)
    unbound = Litestar(
        route_handlers=[_ToolController],
        middleware=[session_config.middleware, SecurityContextMiddleware],
    )
    attach_fake_session_binder(unbound)
    with TestClient(app=unbound, session_config=session_config) as client:
        login(client)
        response = client.get("/tools/file", params={"path": "/workspace/src/app.py"})
    assert response.status_code == 403
