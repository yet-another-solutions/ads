from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from urllib.parse import parse_qs

import httpx2
import pytest

from ads_commons.security import InvalidAccessToken, SecurityContextHolder
from ads_commons_beans import TokenExchangeSettings
from ads_engine.mcp_credentials import ExecutionFailed, McpCredentials, RunCredentials
from engine_fakes import ENGINE_SUBJECT, encode_access_token, exchanged_context


def token_payload(key, *, lifetime=600, **claims):
    return {
        "access_token": encode_access_token(
            key, aud="ads-sandbox-mcp", azp="ads-engine", exp=time.time() + lifetime, **claims
        ),
        "refresh_token": "refresh-secret",
        "token_type": "Bearer",
        "expires_in": lifetime,
        "refresh_expires_in": 1800,
    }


@pytest.fixture
def credential_factory(settings, jwt_verifier):
    return McpCredentials(
        settings,
        TokenExchangeSettings("https://identity.test/token", "ads-engine", "secret", None),
        jwt_verifier,
    )


def test_pair_validation_atomic_read_and_close(credential_factory, jwt_key):
    first = credential_factory._validate(token_payload(jwt_key), ENGINE_SUBJECT, time.time())
    second_payload = token_payload(jwt_key)
    second_payload["refresh_token"] = "rotated-secret"
    second = credential_factory._validate(second_payload, ENGINE_SUBJECT, time.time())
    run = RunCredentials(first, 120)
    assert run.current() is first
    run.replace(second)
    assert run.current() is second
    assert "secret" not in repr(second)
    assert second.context.access_token not in repr(second)
    run.close()
    assert run._pair is None
    with pytest.raises(ExecutionFailed, match="closed"):
        run.current()
    with pytest.raises(ExecutionFailed, match="closed"):
        run.replace(first)


@pytest.mark.parametrize(
    "changes",
    [
        {"access_token": ""},
        {"access_token": "bad"},
        {"refresh_token": ""},
        {"refresh_token": None},
        {"token_type": "Basic"},
        {"expires_in": True},
        {"expires_in": 0},
        {"expires_in": float("nan")},
        {"expires_in": float("inf")},
        {"expires_in": "600"},
        {"refresh_expires_in": None},
        {"refresh_expires_in": -1},
        {"expires_in": 240},
    ],
)
def test_malformed_or_short_pairs_rejected(credential_factory, jwt_key, changes):
    payload = token_payload(jwt_key)
    payload.update(changes)
    with pytest.raises((ValueError, InvalidAccessToken)):
        credential_factory._validate(payload, ENGINE_SUBJECT, time.time())


@pytest.mark.parametrize(
    "claims",
    [
        {"sub": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
        {"sub": "invalid"},
        {"azp": "ads"},
        {"aud": ["ads-sandbox-mcp", "ads"]},
        {"aud": "ads"},
        {"iss": "https://wrong.test"},
        {"realm_access": {"roles": ["user", "admin"]}},
        {"realm_access": {"roles": []}},
        {"resource_access": {"ads": {"roles": ["user"]}}},
        {"exp": time.time() - 10},
    ],
)
def test_identity_or_authority_changes_rejected(credential_factory, jwt_key, claims):
    payload = token_payload(jwt_key)
    payload["access_token"] = encode_access_token(
        jwt_key, **({"aud": "ads-sandbox-mcp", "azp": "ads-engine"} | claims)
    )
    with pytest.raises((ValueError, InvalidAccessToken)):
        credential_factory._validate(payload, ENGINE_SUBJECT, time.time())


def test_requester_never_dispatches_near_expired_or_revoked_token(credential_factory, jwt_key):
    pair = credential_factory._validate(token_payload(jwt_key), ENGINE_SUBJECT, time.time())
    for changed in (
        replace(pair, expires_at=time.time() - 1),
        replace(pair, expires_at=time.time() + 120),
        replace(pair, context=replace(pair.context, roles=frozenset())),
    ):
        with pytest.raises(ExecutionFailed):
            RunCredentials(changed, 120).current()


def test_initial_ste_then_watcher_refresh_after_inbound_expiry(
    settings, jwt_key, jwt_verifier, monkeypatch
):
    """Virtual wall clock advances; no SSO/refresh-expiry timer or sleep polling."""
    factory = McpCredentials(
        replace(settings, mcp_timeout_seconds=2),
        TokenExchangeSettings("https://identity.test/token", "ads-engine", "secret", None),
        jwt_verifier,
    )
    now = time.time()
    issued_at = int(now)
    forms = []
    sleeps = []
    allow_refresh = asyncio.Event()
    renewed = asyncio.Event()
    original_sleep = asyncio.sleep
    original_client = httpx2.AsyncClient

    async def sleep(delay):
        nonlocal now
        sleeps.append(delay)
        await allow_refresh.wait()
        allow_refresh.clear()
        now += delay + 0.01

    async def token_endpoint(request):
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        forms.append(form)
        if len(forms) > 1:
            assert form["grant_type"] == "refresh_token"
            assert form["refresh_token"] == f"refresh-{len(forms) - 1}"
            assert "subject_token" not in form and "audience" not in form and "scope" not in form
        payload = token_payload(jwt_key, lifetime=600)
        payload["access_token"] = encode_access_token(
            jwt_key, aud="ads-sandbox-mcp", azp="ads-engine", exp=now + 600, iat=issued_at
        )
        payload["refresh_token"] = f"refresh-{len(forms)}"
        # Deliberately less than the wait: watcher must not inspect this timer.
        payload["refresh_expires_in"] = 1
        return httpx2.Response(200, json=payload)

    monkeypatch.setattr("ads_engine.mcp_credentials.time.time", lambda: now)
    monkeypatch.setattr("ads_engine.mcp_credentials.asyncio.sleep", sleep)
    monkeypatch.setattr(
        httpx2,
        "AsyncClient",
        lambda **kw: original_client(transport=httpx2.MockTransport(token_endpoint), **kw),
    )
    original_replace = RunCredentials.replace

    def publish(self, pair):
        original_replace(self, pair)
        renewed.set()

    monkeypatch.setattr(RunCredentials, "replace", publish)

    async def scenario():
        inbound = "expired-after-initial-mint"
        with SecurityContextHolder.bound(exchanged_context()):
            async with factory.open(inbound) as run:
                assert forms[0]["subject_token"] == inbound
                assert forms[0]["requested_token_type"].endswith(":refresh_token")
                assert forms[0]["audience"] == "ads-sandbox-mcp"
                for generation in (2, 3):
                    await original_sleep(0)
                    before = run.current()
                    for _ in range(10):
                        assert run.current() is before
                    allow_refresh.set()
                    await asyncio.wait_for(renewed.wait(), 2)
                    renewed.clear()
                    assert run.current().refresh_token == f"refresh-{generation}"
                assert now > issued_at + 600
            assert run._pair is None
        assert len(forms) == 3
        assert all(delay > 590 for delay in sleeps)

    asyncio.run(scenario())


def test_watcher_failure_cancels_work_and_drops_pair(credential_factory, jwt_key, monkeypatch):
    pair = credential_factory._validate(token_payload(jwt_key), ENGINE_SUBJECT, time.time())
    minted = 0
    original_sleep = asyncio.sleep

    async def request(client, grant, subject):
        nonlocal minted
        minted += 1
        if minted == 1:
            return replace(pair, expires_at=time.time() + 240.01)
        raise ExecutionFailed("MCP credential mint or refresh failed")

    monkeypatch.setattr(credential_factory, "_request", request)

    async def scenario():
        run = None
        with SecurityContextHolder.bound(exchanged_context()):
            with pytest.raises(ExceptionGroup):
                async with credential_factory.open("inbound") as run:
                    await original_sleep(10)
        assert run is not None and run._pair is None
        assert minted == 2

    asyncio.run(scenario())


def test_cancel_during_refresh_cannot_resurrect_pair(credential_factory, jwt_key, monkeypatch):
    pair = credential_factory._validate(token_payload(jwt_key), ENGINE_SUBJECT, time.time())
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    runs = []
    calls = 0

    async def request(client, grant, subject):
        nonlocal calls
        calls += 1
        if calls == 1:
            return replace(pair, expires_at=time.time() + 240.01)
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(credential_factory, "_request", request)

    async def scenario():
        async def work():
            with SecurityContextHolder.bound(exchanged_context()):
                async with credential_factory.open("inbound") as run:
                    runs.append(run)
                    await asyncio.Event().wait()

        task = asyncio.create_task(work())
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert cancelled.is_set()
        assert runs[0]._pair is None
        assert calls == 2

    asyncio.run(scenario())


def test_concurrent_users_have_independent_pairs_and_teardown(
    credential_factory, jwt_key, monkeypatch
):
    subjects = [ENGINE_SUBJECT, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
    real_client = httpx2.AsyncClient

    async def endpoint(request):
        form = parse_qs(request.content.decode())
        subject = form["subject_token"][0]
        payload = token_payload(jwt_key, sub=subject)
        payload["refresh_token"] = "refresh-" + subject
        return httpx2.Response(200, json=payload)

    monkeypatch.setattr(
        httpx2,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx2.MockTransport(endpoint), **kw),
    )
    ready = [asyncio.Event(), asyncio.Event()]
    release = [asyncio.Event(), asyncio.Event()]
    runs = {}

    async def work(index):
        subject = subjects[index]
        with SecurityContextHolder.bound(replace(exchanged_context(), subject=subject)):
            async with credential_factory.open(subject) as run:
                runs[index] = run
                ready[index].set()
                await release[index].wait()
                assert run.current().context.subject == subject
                assert run.current().refresh_token == "refresh-" + subject

    async def scenario():
        async with asyncio.TaskGroup() as tasks:
            first = tasks.create_task(work(0))
            tasks.create_task(work(1))
            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in ready)), 2)
            assert runs[0] is not runs[1]
            release[0].set()
            await first
            assert runs[0]._pair is None
            assert runs[1].current().context.subject == subjects[1]
            release[1].set()
        assert runs[1]._pair is None

    asyncio.run(scenario())


def test_behind_a_guardrail_the_credential_is_minted_for_it(
    settings, jwt_verifier, jwt_key, monkeypatch
):
    # Keycloak lets the guardrail exchange only a token whose audience names it.
    from ads_engine.config import GuardrailSettings, Workspace

    guarded = replace(
        settings,
        guardrail=GuardrailSettings(
            "https://guardrail.test", "guardrail-token", Workspace("ads", "r", "test", "/workspace")
        ),
    )
    factory = McpCredentials(
        guarded,
        TokenExchangeSettings("https://identity.test/token", "ads-engine", "secret", None),
        jwt_verifier,
    )
    forms = []
    original_client = httpx2.AsyncClient

    def token_endpoint(request):
        forms.append({key: value[0] for key, value in parse_qs(request.content.decode()).items()})
        return httpx2.Response(
            200,
            json=token_payload(jwt_key)
            | {
                "access_token": encode_access_token(
                    jwt_key, aud="ads-guardrail", azp="ads-engine", exp=time.time() + 600
                )
            },
        )

    monkeypatch.setattr(
        httpx2,
        "AsyncClient",
        lambda **kw: original_client(transport=httpx2.MockTransport(token_endpoint), **kw),
    )

    async def scenario():
        with SecurityContextHolder.bound(exchanged_context()):
            async with factory.open("inbound") as run:
                assert run.current().context.access_token

    asyncio.run(scenario())
    assert forms[0]["audience"] == "ads-guardrail"
    with pytest.raises((ValueError, InvalidAccessToken)):
        factory._validate(token_payload(jwt_key), ENGINE_SUBJECT, time.time())
