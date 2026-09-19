from __future__ import annotations

import ssl
from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide
from jwt import PyJWKClient

from ads_commons.security import (
    AccessTokenVerifier,
    jwks_uri_from_well_known,
    token_endpoint_from_well_known,
)
from ads_commons_beans import (
    JwtVerifier,
    JwtVerifierSettings,
    TokenExchange,
    TokenExchangeSettings,
)
from ads_guardrail.config import Settings
from ads_guardrail.guardrail import Guardrail
from ads_guardrail.proxy import Proxy
from ads_guardrail.scanner import (
    HttpInjectionScanner,
    InjectionScanner,
    UnconfiguredInjectionScanner,
)
from ads_guardrail.upstream import UpstreamTokens
from ads_policy.audit import AuditSink, BufferedAuditSink, RabbitAuditSink
from ads_policy.build import identity
from ads_policy.client import PolicyClient, build_policy_client
from ads_policy.config import PayloadInspection


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


def build_upstream_tokens(
    settings: Settings, verifier: AccessTokenVerifier | None
) -> UpstreamTokens | None:
    """Only servers that name an audience need one; the minted token is verified for it."""
    if not any(server.audience for server in settings.mcp_servers) or verifier is None:
        return None
    context = (
        ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
        if settings.tls_ca_bundle is not None
        else None
    )
    return UpstreamTokens(
        TokenExchange(
            TokenExchangeSettings(
                token_endpoint=token_endpoint_from_well_known(
                    settings.keycloak_well_known_url, context
                ),
                client_id=settings.keycloak_client_id,
                client_secret=settings.keycloak_client_secret,
                ssl_context=context,
            ),
            verifier,
        )
    )


def build_injection_scanner(settings: Settings) -> InjectionScanner:
    if not settings.injection_scanner_url:
        return UnconfiguredInjectionScanner()
    tls: ssl.SSLContext | bool = True
    if settings.tls_ca_bundle is not None:
        tls = ssl.create_default_context(cafile=str(settings.tls_ca_bundle))
    return HttpInjectionScanner(
        settings.injection_scanner_url,
        settings.injection_scanner_api_token,
        tls,
        settings.injection_scanner_timeout_seconds,
    )


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        client: PolicyClient | None = None,
        sink: AuditSink | None = None,
        person_token_verifier: AccessTokenVerifier | None = None,
        injection_scanner: InjectionScanner | None = None,
        upstream_tokens: UpstreamTokens | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._client = client
        self._sink = sink
        self._person_token_verifier = person_token_verifier
        self._injection_scanner = injection_scanner
        self._upstream_tokens = upstream_tokens

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    def inspection(self, settings: Settings) -> PayloadInspection:
        return PayloadInspection(denied_message=settings.denied_message)

    @provide(scope=Scope.APP)
    def policy_client(self, settings: Settings) -> PolicyClient:
        if self._client is not None:
            return self._client
        return build_policy_client(
            settings.policy_url,
            settings.policy_api_token,
            denied_message=settings.denied_message,
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
        self, settings: Settings, broker: AbstractRobustConnection | None
    ) -> BufferedAuditSink:
        sink = self._sink if broker is None else RabbitAuditSink(broker)
        assert sink is not None
        return BufferedAuditSink(sink, settings.audit_backlog, decided_by=identity("ads-guardrail"))

    @provide(scope=Scope.APP)
    def guardrail(
        self,
        settings: Settings,
        client: PolicyClient,
        audit: BufferedAuditSink,
        inspection: PayloadInspection,
    ) -> Guardrail:
        return Guardrail(
            settings=settings,
            client=client,
            audit=audit,
            inspection=inspection,
            person_token_verifier=(
                self._person_token_verifier or build_person_token_verifier(settings)
            ),
        )

    @provide(scope=Scope.APP)
    async def injection_scanner(self, settings: Settings) -> AsyncIterator[InjectionScanner]:
        scanner = self._injection_scanner or build_injection_scanner(settings)
        try:
            yield scanner
        finally:
            await scanner.close()

    @provide(scope=Scope.APP)
    def upstream_tokens(self, settings: Settings) -> UpstreamTokens | None:
        if self._upstream_tokens is not None:
            return self._upstream_tokens
        return build_upstream_tokens(
            settings, self._person_token_verifier or build_person_token_verifier(settings)
        )

    @provide(scope=Scope.APP)
    async def proxy(
        self,
        settings: Settings,
        guardrail: Guardrail,
        injection_scanner: InjectionScanner,
        upstream_tokens: UpstreamTokens | None,
    ) -> AsyncIterator[Proxy]:
        proxy = Proxy(settings, guardrail, injection_scanner, upstream_tokens)
        try:
            yield proxy
        finally:
            await proxy.close()
