from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any

import aiohttp
import msgspec
import pytest

from ads_audit.blocking import ConversationGuard
from ads_audit.consumer import AuditConsumer
from ads_audit.repository import InMemoryAuditRepository, fixed_unit_of_work
from ads_engine.chat import StreamDelta
from ads_engine.config import Settings as EngineSettings
from ads_engine.config import ToolSettings, Workspace
from ads_engine.store import ActiveSessionStore
from ads_engine.tooling import ToolingChatStreamer
from ads_guardrail.app import create_app as create_guardrail
from ads_guardrail.config import Settings as GuardrailSettings
from ads_guardrail.contract import McpServer
from ads_injection_scanner.app import create_app as create_scanner
from ads_injection_scanner.classifier import InjectionClassifier, PromptGuardClassifier
from ads_injection_scanner.config import Settings as ScannerSettings
from ads_mcp_probe.app import create_app as create_probe
from ads_mcp_probe.tools import FAKE_AWS_ACCESS_KEY, INJECTED_INSTRUCTION
from ads_policy.audit import BufferedAuditSink, CollectingAuditSink
from ads_policy.blocks import InMemoryConversationBlocks
from ads_policy.config import GovernanceSettings
from ads_policy.contract import (
    DEFAULT_RESPONSE,
    AuditEvent,
    Effect,
    Interception,
    Placement,
    Side,
    Site,
)
from ads_policy.pdp import PolicyDecisionPoint
from ads_policy.policy import load_policy
from ads_policy.run import InMemoryRunStore
from ads_policy.service import PolicyService
from chain_helpers import (
    ALICE,
    INJECTION_MARKER,
    MCP_AUDIENCE,
    PERSON_TOKEN_VERIFIER,
    InProcessPolicyClient,
    KeycloakExchange,
    MarkerClassifier,
    PolicyServiceBlocker,
    ScriptedModel,
    engine_request,
    eventually,
    said,
    served,
    tool_call,
)

REPOSITORY = Path(__file__).resolve().parents[2]
MODEL_DIR = REPOSITORY / "models" / "injection-classifier"
GOVERNANCE = GovernanceSettings()
WORKDIR = GOVERNANCE.workdir
CHAT = uuid.UUID("44444444-4444-4444-8444-444444444444")
OTHER_CHAT = uuid.UUID("55555555-5555-4555-8555-555555555555")
SERVICE_TOKEN = "chain-service-token-32-bytes-long"

KATA_VM = Site(
    placement=Placement.CLUSTER,
    runtime_class_name=GOVERNANCE.vm_runtime_class,
    node_labels={
        GOVERNANCE.sandbox_node_label: GOVERNANCE.node_label_value,
        GOVERNANCE.application_node_label: GOVERNANCE.node_label_value,
    },
)
APPLICATION_NODE = Site(
    placement=Placement.CLUSTER,
    node_labels={GOVERNANCE.application_node_label: GOVERNANCE.node_label_value},
)

EXAMPLE_POLICY = load_policy(
    msgspec.yaml.decode(
        (REPOSITORY / "charts" / "ads" / "policy.example.yaml").read_bytes(),
        type=dict[str, Any],
    )
)
INJECTION_ENFORCED = Interception(response=Side(checks=DEFAULT_RESPONSE.checks))


class Chain:
    def __init__(
        self,
        tmp_path: Path,
        interception: Interception | None = None,
        conversation_budget_limit: int = 30,
        classifier: InjectionClassifier | None = None,
    ) -> None:
        self.classifier = classifier or MarkerClassifier()
        policy = replace(EXAMPLE_POLICY, interception=interception or EXAMPLE_POLICY.interception)
        self.policy_journal = CollectingAuditSink()
        self.policy = PolicyService(
            PolicyDecisionPoint(policy),
            InMemoryRunStore(),
            BufferedAuditSink(self.policy_journal),
            blocks=InMemoryConversationBlocks(),
        )
        self.guardrail_journal = CollectingAuditSink()
        self.audit = InMemoryAuditRepository()
        self.audit_consumer = AuditConsumer(
            None,  # type: ignore[arg-type]
            fixed_unit_of_work(self.audit),
            guard=ConversationGuard(
                PolicyServiceBlocker(self.policy), budget_limit=conversation_budget_limit
            ),
        )
        self.exchange = KeycloakExchange()
        self.tmp_path = tmp_path
        self.store = ActiveSessionStore(_engine_settings())
        self.audited = 0
        self.guardrail_url = ""

    def start(self, stack: ExitStack) -> None:
        cert = self.tmp_path / "tls.pem"
        cert.write_text("unused")
        probe_url = stack.enter_context(served(create_probe()))
        scanner_url = stack.enter_context(
            served(
                create_scanner(
                    ScannerSettings(
                        api_token=SERVICE_TOKEN,
                        tls_cert_path=cert,
                        tls_key_path=cert,
                        model_dir=self.tmp_path,
                    ),
                    classifier=self.classifier,
                )
            )
        )
        guardrail_settings = GuardrailSettings(
            api_token=SERVICE_TOKEN,
            tls_cert_path=cert,
            tls_key_path=cert,
            policy_url="https://policy.unused",
            policy_api_token=SERVICE_TOKEN,
            amqp_url="amqp://unused",
            attributes={"repo.write": "true", "agent": "true"},
            audit_flush_seconds=0.02,
            mcp_servers=(
                McpServer("probe-vm", f"{probe_url}/mcp", KATA_VM),
                McpServer("probe-container", f"{probe_url}/mcp", APPLICATION_NODE),
            ),
            person_token_audience=MCP_AUDIENCE,
            keycloak_well_known_url="https://keycloak.test/.well-known/openid-configuration",
            keycloak_issuer="https://keycloak.test/realms/ads",
            injection_scanner_url=scanner_url,
            injection_scanner_api_token=SERVICE_TOKEN,
        )
        self.guardrail_url = stack.enter_context(
            served(
                create_guardrail(
                    guardrail_settings,
                    InProcessPolicyClient(self.policy),
                    self.guardrail_journal,
                    PERSON_TOKEN_VERIFIER,
                )
            )
        )

    async def ask(
        self, http: aiohttp.ClientSession, model: ScriptedModel, chat: uuid.UUID = CHAT
    ) -> list[StreamDelta]:
        streamer = ToolingChatStreamer(
            ToolSettings(
                mcp_servers=("probe-vm", "probe-container"),
                guardrail_url=self.guardrail_url,
                guardrail_api_token=SERVICE_TOKEN,
                mcp_audience=MCP_AUDIENCE,
                workspace=Workspace(
                    project="ads", repo="yet-another-solutions/ads", env="test", workdir=WORKDIR
                ),
                retry_pause_seconds=0.0,
                timeout_seconds=10.0,
            ),
            http,
            self.exchange,
            self.store,
            model_factory=lambda request: model,
        )
        return [delta async for delta in streamer.stream(engine_request(chat))]

    async def journal(self, expected_guardrail_rows: int = 0) -> list[AuditEvent]:
        await self.policy.flush_audit()
        await eventually(lambda: len(self.guardrail_journal.events()) >= expected_guardrail_rows)
        return [*self.policy_journal.events(), *self.guardrail_journal.events()]

    async def audit_everything(self, expected_guardrail_rows: int = 0) -> None:
        events = await self.journal(expected_guardrail_rows)
        for event in events[self.audited :]:
            await self.audit_consumer.handle(_Delivery(event))  # type: ignore[arg-type]
        self.audited = len(events)


class _Delivery:
    def __init__(self, event: AuditEvent) -> None:
        self.body = msgspec.json.encode(event)

    async def ack(self) -> None:
        return None

    async def nack(self, requeue: bool = True) -> None:
        raise AssertionError("the audit service could not journal an event")

    async def reject(self, requeue: bool = True) -> None:
        raise AssertionError("the audit service rejected an event")


def _engine_settings() -> EngineSettings:
    return EngineSettings(
        kafka_bootstrap_servers="kafka.test:9092",
        request_topic="ads.engine.request",
        output_topic="ads.engine.output",
        consumer_group="ads-engine",
        database_url="sqlite:///:memory:",
        ping_interval_seconds=10,
        ack_timeout_seconds=10,
        keycloak_well_known_url="https://keycloak.test/.well-known/openid-configuration",
        keycloak_issuer="https://keycloak.test/realms/ads",
        keycloak_audience="ads-engine",
        keycloak_client_id="ads",
        keycloak_client_secret="secret",
        ack_audience="ads",
        allowed_callers=frozenset({"ads"}),
        tls_ca_bundle=None,
    )


ChainScenario = Callable[[Chain, aiohttp.ClientSession], Awaitable[None]]


def _through_the_chain(chain: Chain, scenario: ChainScenario) -> None:
    async def main() -> None:
        async with aiohttp.ClientSession() as http:
            await scenario(chain, http)

    with ExitStack() as stack:
        chain.start(stack)
        asyncio.run(main())


def _notices(deltas: list[StreamDelta]) -> list[tuple[str, str]]:
    return [(d.notice.kind, d.notice.tool) for d in deltas if d.notice is not None]


def _rows(events: list[AuditEvent], rule_id: str) -> list[AuditEvent]:
    return [event for event in events if event.rule_id == rule_id]


def test_a_permitted_call_goes_through_every_service(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [
                [tool_call("probe-vm__read_file", {"path": f"{WORKDIR}/src/app.py"})],
                [said("read it")],
            ]
        )
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == []
        assert model.tool_result() == f"probe: contents of {WORKDIR}/src/app.py"
        assert "probe-container__read_file" in model.offered
        assert chain.exchange.audiences == [MCP_AUDIENCE]
        (allowed,) = _rows(await chain.journal(), "fs.read.workdir")
        assert allowed.effect is Effect.ALLOW
        assert allowed.subject == ALICE
        assert allowed.conversation == str(CHAT)

    _through_the_chain(Chain(tmp_path), scenario)


def test_every_message_of_a_chat_shares_one_run(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        for _ in range(2):
            await chain.ask(
                http,
                ScriptedModel([[tool_call("probe-vm__echo", {"text": "hello"})], [said("ok")]]),
            )
        held = await chain.policy.held_by(f"user:{ALICE}")
        assert [run.conversation for run in held] == [str(CHAT)]

    _through_the_chain(Chain(tmp_path), scenario)


def test_the_same_tool_is_decided_by_where_its_server_runs(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [
                [tool_call("probe-vm__run_command", {"command": "uv sync"}, "vm")],
                [tool_call("probe-container__run_command", {"command": "uv sync"}, "container")],
                [said("done")],
            ]
        )
        deltas = await chain.ask(http, model)
        assert model.tool_result(1) == "probe: would run uv sync"
        assert "refused" in model.tool_result(2)
        assert _notices(deltas) == [("tool-refused", "probe-container/run_command")]

    _through_the_chain(Chain(tmp_path), scenario)


def test_reading_outside_the_workdir_is_refused_and_journalled(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [[tool_call("probe-vm__read_file", {"path": "/etc/shadow"})], [said("no")]]
        )
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == [("tool-refused", "probe-vm/read_file")]
        (refused,) = _rows(await chain.journal(), "fs.read.outside")
        assert refused.effect is Effect.DENY
        assert refused.conversation == str(CHAT)

    _through_the_chain(Chain(tmp_path), scenario)


def test_a_tool_nothing_binds_never_reaches_the_server(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel([[tool_call("probe-vm__diagnostics", {})], [said("no")]])
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == [("tool-refused", "probe-vm/diagnostics")]
        assert "unbound tool was reached" not in model.tool_result()
        assert _rows(await chain.journal(), "binding.missing") != []

    _through_the_chain(Chain(tmp_path), scenario)


def test_a_secret_in_the_arguments_never_leaves(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [
                [tool_call("probe-vm__echo", {"text": f"key={FAKE_AWS_ACCESS_KEY}"})],
                [said("no")],
            ]
        )
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == [("tool-refused", "probe-vm/echo")]
        assert FAKE_AWS_ACCESS_KEY not in model.tool_result()
        assert _rows(await chain.journal(expected_guardrail_rows=1), "payload.leak") != []

    _through_the_chain(Chain(tmp_path), scenario)


def test_a_secret_in_the_result_is_cut_out(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel([[tool_call("probe-vm__env_config", {})], [said("ok")]])
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == []
        assert FAKE_AWS_ACCESS_KEY not in model.tool_result()
        assert "[redacted:aws-access-token]" in model.tool_result()

    _through_the_chain(Chain(tmp_path), scenario)


def test_by_default_an_injection_is_recorded_and_passed_on(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel([[tool_call("probe-vm__release_notes", {})], [said("ok")]])
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == []
        assert INJECTED_INSTRUCTION in model.tool_result()
        (recorded,) = _rows(await chain.journal(expected_guardrail_rows=1), "payload.injection")
        assert recorded.weight == 0

    _through_the_chain(Chain(tmp_path), scenario)


def test_an_enforced_injection_is_withheld_and_the_person_told_why(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel([[tool_call("probe-vm__release_notes", {})], [said("ok")]])
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == [("prompt-injection", "probe-vm/release_notes")]
        assert INJECTION_MARKER not in model.tool_result().lower()
        (withheld,) = _rows(await chain.journal(expected_guardrail_rows=1), "payload.injection")
        assert withheld.weight == GOVERNANCE.injection_weight

    _through_the_chain(Chain(tmp_path, interception=INJECTION_ENFORCED), scenario)


def test_an_injection_in_a_streamed_answer_is_withheld(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [
                [tool_call("probe-vm__tail_log", {"text": "streamed and clean"}, "clean")],
                [tool_call("probe-vm__tail_log", {"text": INJECTION_MARKER}, "poisoned")],
                [said("ok")],
            ]
        )
        deltas = await chain.ask(http, model)
        assert model.tool_result(1) == "streamed and clean"
        assert INJECTION_MARKER not in model.tool_result(2).lower()
        assert _notices(deltas) == [("prompt-injection", "probe-vm/tail_log")]

    _through_the_chain(Chain(tmp_path, interception=INJECTION_ENFORCED), scenario)


def test_a_chat_over_its_budget_loses_its_tools_and_only_that_chat(tmp_path: Path) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        outside = {"path": "/etc/shadow"}
        await chain.ask(
            http,
            ScriptedModel(
                [
                    [tool_call("probe-vm__read_file", outside, "first")],
                    [tool_call("probe-vm__read_file", outside, "again")],
                    [said("stopped")],
                ]
            ),
        )
        await chain.audit_everything()
        assert await chain.audit.conversation_block(str(CHAT)) is not None

        blocked = ScriptedModel(
            [[tool_call("probe-vm__read_file", {"path": f"{WORKDIR}/a.py"})], [said("?")]]
        )
        assert _notices(await chain.ask(http, blocked)) == [("tool-refused", "probe-vm/read_file")]
        assert _rows(await chain.journal(), "conversation.revoked") != []

        elsewhere = ScriptedModel(
            [[tool_call("probe-vm__read_file", {"path": f"{WORKDIR}/a.py"})], [said("ok")]]
        )
        assert _notices(await chain.ask(http, elsewhere, OTHER_CHAT)) == []

    _through_the_chain(Chain(tmp_path, conversation_budget_limit=10), scenario)


@pytest.mark.parametrize("server", ["probe-vm", "probe-container"])
def test_both_servers_offer_the_probe_tools(tmp_path: Path, server: str) -> None:
    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel([[said("hi")]])
        await chain.ask(http, model)
        assert {
            f"{server}__{tool}"
            for tool in ("echo", "env_config", "release_notes", "run_command")
        } <= set(
            model.offered
        )

    _through_the_chain(Chain(tmp_path), scenario)


@pytest.mark.skipif(
    not (MODEL_DIR / "model.onnx").is_file(),
    reason="the injection model is not in models/injection-classifier",
)
def test_the_real_classifier_withholds_the_probe_injection(tmp_path: Path) -> None:
    classifier = PromptGuardClassifier.from_directory(
        MODEL_DIR, window_tokens=512, window_overlap_tokens=64, malicious_label_index=1
    )

    async def scenario(chain: Chain, http: aiohttp.ClientSession) -> None:
        model = ScriptedModel(
            [
                [tool_call("probe-vm__release_notes", {}, "poisoned")],
                [tool_call("probe-vm__read_file", {"path": f"{WORKDIR}/src/app.py"}, "clean")],
                [said("ok")],
            ]
        )
        deltas = await chain.ask(http, model)
        assert _notices(deltas) == [("prompt-injection", "probe-vm/release_notes")]
        assert model.tool_result(2) == f"probe: contents of {WORKDIR}/src/app.py"

    _through_the_chain(
        Chain(tmp_path, interception=INJECTION_ENFORCED, classifier=classifier), scenario
    )
