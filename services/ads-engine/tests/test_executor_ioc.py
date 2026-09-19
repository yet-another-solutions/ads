from ads_engine.executor import ExecutorChatStreamer
from ads_engine.ioc import AcknowledgeTokens, AppProvider
from engine_fakes import exchanged_context


def test_ack_optional_scope_does_not_become_mcp_default():
    class Exchange:
        calls = []

        def mint(self, audience, *, scope=None):
            self.calls.append((audience, scope))
            return exchanged_context()

    exchange = Exchange()
    tokens = AcknowledgeTokens(exchange)
    assert tokens.mint("ads").access_token == "exchanged-token"
    assert exchange.calls == [("ads", "ads-engine-ack")]


def test_default_provider_has_executor_not_thinker(settings):
    provider = AppProvider(settings)
    assert any(factory.source is ExecutorChatStreamer for factory in provider.factories)
