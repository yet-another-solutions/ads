import asyncio
import ssl

import httpx2
import msgspec
import pytest
from langchain_core.messages import AIMessage

from ads_commons.context_compactor import CompactRequest
from ads_commons.context_meter import MeterRequest
from ads_context_runtime.frames import ContextFailure, ContextOverflow, LangChainFrameModel
from ads_context_runtime.http import ContextClients
from context_fakes import memory, model_settings


@pytest.mark.parametrize("status", [200, 401, 403, 422, 500])
def test_context_rest_uses_fresh_scoped_exchange_and_no_fallback(monkeypatch, status):
    calls, requests = [], []

    class Exchange:
        def exchange(self, audience, subject_token=None, *, scope=None):
            calls.append((audience, subject_token, scope))
            return "exchanged-secret"

    def respond(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer exchanged-secret"
        assert b"inbound-secret" not in request.content
        body = (
            {"estimated_tokens": 42}
            if request.url.path == "/meter"
            else msgspec.to_builtins(memory())
        )
        return httpx2.Response(status, json=body)

    original = httpx2.AsyncClient
    monkeypatch.setattr(
        "ads_context_runtime.http.httpx2.AsyncClient",
        lambda **kwargs: original(transport=httpx2.MockTransport(respond), **kwargs),
    )
    client = ContextClients(
        Exchange(),
        "https://meter.test/meter",
        "https://compactor.test/compact",
        ssl.create_default_context(),
        "inbound-secret",
    )

    async def scenario():
        for _ in range(2):
            if status == 200:
                assert (await client.meter(MeterRequest("glm-5.3", []))).estimated_tokens == 42
            else:
                with pytest.raises(ContextFailure, match="context_service_failed"):
                    await client.meter(MeterRequest("glm-5.3", []))
        if status == 200:
            await client.compact(CompactRequest([], model_settings(), 50))

    asyncio.run(scenario())
    assert calls[:2] == [("ads-context-meter", "inbound-secret", "ads-engine-context-meter")] * 2
    if status == 200:
        assert calls[2] == (
            "ads-context-compactor",
            "inbound-secret",
            "ads-engine-context-compactor",
        )
        assert b"exchanged-secret" not in requests[-1].content


@pytest.mark.parametrize(
    "code,error", [("context_length_exceeded", ContextOverflow), ("unknown", ContextFailure)]
)
def test_langchain_frame_model_has_no_retries_bounded_output_and_safe_errors(
    monkeypatch, code, error
):
    options = {}

    class ProviderError(Exception):
        body = {"error": {"code": code}}

    class Chat:
        def __init__(self, **kwargs):
            options.update(kwargs)

        async def ainvoke(self, messages):
            raise ProviderError("private-response")

    monkeypatch.setattr("ads_context_runtime.frames.ChatOpenAI", Chat)
    model = LangChainFrameModel(model_settings())
    with pytest.raises(error) as exc:
        asyncio.run(model.invoke([], [], 321))
    assert options["max_completion_tokens"] == 321 and options["max_retries"] == 0
    assert callable(options["api_key"])
    assert "private" not in str(exc.value)


def test_langchain_frame_model_never_binds_tools_in_finalization(monkeypatch):
    class Chat:
        def __init__(self, **kwargs):
            pass

        def bind_tools(self, *args, **kwargs):
            raise AssertionError("finalization must not receive tools")

        async def ainvoke(self, messages):
            return AIMessage("final")

    monkeypatch.setattr("ads_context_runtime.frames.ChatOpenAI", Chat)
    assert asyncio.run(LangChainFrameModel(model_settings()).invoke([], [], 100)).content == "final"


def test_unset_completion_cap_is_omitted_from_provider_request(monkeypatch):
    options = {}

    class Chat:
        def __init__(self, **kwargs):
            options.update(kwargs)

        async def ainvoke(self, messages):
            return AIMessage("final")

    monkeypatch.setattr("ads_context_runtime.frames.ChatOpenAI", Chat)
    result = asyncio.run(LangChainFrameModel(model_settings()).invoke([], [], None))
    assert result.content == "final"
    assert "max_completion_tokens" not in options and "max_tokens" not in options


@pytest.mark.parametrize("reason", ["no_safe_fitting_prefix", "provider secret payload"])
def test_compaction_failure_reason_is_typed_and_allowlisted(monkeypatch, reason):
    class Exchange:
        def exchange(self, *args, **kwargs):
            return "exchanged-secret"

    original = httpx2.AsyncClient
    monkeypatch.setattr(
        "ads_context_runtime.http.httpx2.AsyncClient",
        lambda **kwargs: original(
            transport=httpx2.MockTransport(
                lambda request: httpx2.Response(
                    422, json={"detail": "context request failed", "reason": reason}
                )
            ),
            **kwargs,
        ),
    )
    client = ContextClients(
        Exchange(),
        "https://meter.test/meter",
        "https://compactor.test/compact",
        ssl.create_default_context(),
        "inbound-secret",
    )
    with pytest.raises(ContextFailure) as failure:
        asyncio.run(client.compact(CompactRequest([], model_settings(), 50)))
    assert str(failure.value) == (
        "no_safe_fitting_prefix" if reason == "no_safe_fitting_prefix" else "context_service_failed"
    )
