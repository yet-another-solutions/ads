from __future__ import annotations

from dishka import Provider, Scope, provide

from ads_engine.chat import ChatStreamer, LangChainChatStreamer
from ads_engine.config import Settings
from ads_engine.store import ActiveSessionStore


class AppProvider(Provider):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self._settings = settings

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def store(self, settings: Settings) -> ActiveSessionStore:
        return ActiveSessionStore(settings.database_url)

    @provide(scope=Scope.APP)
    def chat(self) -> ChatStreamer:
        return LangChainChatStreamer()
