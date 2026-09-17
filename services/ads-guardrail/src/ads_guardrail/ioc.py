from __future__ import annotations

import ssl
from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide
from jwt import PyJWKClient

from ads_commons.security import AccessTokenVerifier, jwks_uri_from_well_known
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_guardrail.config import Settings
from ads_guardrail.guardrail import Guardrail
from ads_guardrail.proxy import Proxy
from ads_policy.audit import AuditSink, BufferedAuditSink, RabbitAuditSink
from ads_policy.build import identity
from ads_policy.client import PolicyClient, build_policy_client
from ads_policy.config import GovernanceSettings


def build_person_token_verifier(settings: Settings) -> AccessTokenVerifier | None:
    audience = settings.person_token_audience
    if not audience:
        return None
    context = (
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        if settings.tls_ca_bundle is not None
        else None
    )
    jwks_uri = jwks_uri_from_well_known(settings.keycloak_well_known_url, context)
    return JwtVerifier(
        JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience=audience,
            client_id=audience,
            jwks_uri=jwks_uri,
            ssl_context=context,
        ),
        PyJWKClient(jwks_uri, ssl_context=context),
    )


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        client: PolicyClient | None = None,
        sink: AuditSink | None = None,
        person_token_verifier: AccessTokenVerifier | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._client = client
        self._sink = sink
        self._person_token_verifier = person_token_verifier

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def governance(self) -> GovernanceSettings:
        return GovernanceSettings()

    @provide(scope=Scope.APP)
    def policy_client(self, settings: Settings, governance: GovernanceSettings) -> PolicyClient:
        if self._client is not None:
            return self._client
        return build_policy_client(
            settings.policy_url,
            settings.policy_api_token,
            denied_message=governance.denied_message,
            ca_bundle=settings.tls_ca_bundle,
        )

    @provide(scope=Scope.APP)
    async def broker(self, settings: Settings) -> AsyncIterator[AbstractRobustConnection | None]:
        if self._sink is not None:
            yield None
            return
        connection = await aio_pika.connect_robust(settings.amqp_url)
        try:
            yield connection
        finally:
            await connection.close()

    @provide(scope=Scope.APP)
    def audit(
        self, governance: GovernanceSettings, broker: AbstractRobustConnection | None
    ) -> BufferedAuditSink:
        sink = self._sink if broker is None else RabbitAuditSink(broker)
        assert sink is not None
        return BufferedAuditSink(sink, governance, decided_by=identity("ads-guardrail"))

    @provide(scope=Scope.APP)
    def guardrail(
        self,
        settings: Settings,
        client: PolicyClient,
        audit: BufferedAuditSink,
        governance: GovernanceSettings,
    ) -> Guardrail:
        return Guardrail(
            settings=settings,
            client=client,
            audit=audit,
            governance=governance,
            person_token_verifier=(
                self._person_token_verifier or build_person_token_verifier(settings)
            ),
        )

    @provide(scope=Scope.APP)
    async def proxy(self, settings: Settings, guardrail: Guardrail) -> AsyncIterator[Proxy]:
        proxy = Proxy(settings, guardrail)
        try:
            yield proxy
        finally:
            await proxy.close()
