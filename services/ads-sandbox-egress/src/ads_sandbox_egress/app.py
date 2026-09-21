from __future__ import annotations

from dishka import Provider, Scope, make_async_container, provide
from dishka.integrations.litestar import LitestarProvider, setup_dishka
from litestar import Litestar

from ads_commons_beans import JwtVerifier
from ads_sandbox_egress.configuration import (
    ConfigurationService,
    LocalHealth,
    PairIdentity,
    PolicyStore,
)
from ads_sandbox_egress.control import configure, ping


class ControlProvider(Provider):
    def __init__(
        self, pair: PairIdentity, store: PolicyStore, health: LocalHealth, verifier: JwtVerifier
    ) -> None:
        super().__init__()
        self._pair, self._store, self._health, self._verifier = pair, store, health, verifier

    @provide(scope=Scope.APP)
    def pair(self) -> PairIdentity:
        return self._pair

    @provide(scope=Scope.APP)
    def store(self) -> PolicyStore:
        return self._store

    @provide(scope=Scope.APP)
    def health(self) -> LocalHealth:
        return self._health

    @provide(scope=Scope.APP)
    def verifier(self) -> JwtVerifier:
        return self._verifier

    service = provide(ConfigurationService, scope=Scope.APP)


def create_app(
    pair: PairIdentity, store: PolicyStore, health: LocalHealth, verifier: JwtVerifier
) -> Litestar:
    """No permissive defaults: the full runtime must supply its real local health port.

    This component does not start a listener or construct a fake data plane. The
    eventual runtime must pre-load TLS, construct the configured commons verifier,
    and pass the exact same PolicyStore to its application traffic handlers.
    """
    container = make_async_container(
        ControlProvider(pair, store, health, verifier), LitestarProvider()
    )

    async def shutdown() -> None:
        await store.close()
        await container.close()

    app = Litestar(
        route_handlers=[configure, ping],
        request_max_body_size=1024 * 1024,
        on_shutdown=[shutdown],
        openapi_config=None,
    )
    setup_dishka(container, app)
    return app
