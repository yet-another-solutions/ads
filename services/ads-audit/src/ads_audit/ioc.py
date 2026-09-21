from __future__ import annotations

import ssl
from collections.abc import AsyncIterator

import aio_pika
from aio_pika.abc import AbstractRobustConnection
from dishka import Provider, Scope, provide
from jwt import PyJWKClient
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ads_audit.auditor import AuditorDesk
from ads_audit.blocking import (
    ConversationGuard,
    HttpPolicyBlocker,
    PolicyBlocker,
    UnconfiguredPolicyBlocker,
)
from ads_audit.config import Settings
from ads_audit.policy_sources import HttpPolicySources, PolicySources, UnconfiguredPolicySources
from ads_audit.refresh_tokens import SqlRefreshTokenStore
from ads_audit.repository import AuditRepository, SqlAuditRepository
from ads_audit.service import AuditService
from ads_commons.security import jwks_uri_from_well_known
from ads_commons_beans import JwtVerifier, JwtVerifierSettings
from ads_commons_web.oidc import OidcClient, OidcSettings
from ads_commons_web.session_binder import SessionBinder
from ads_policy.client import HttpPolicyClient


class AppProvider(Provider):
    def __init__(
        self,
        settings: Settings,
        repository: AuditRepository | None = None,
        connection: AbstractRobustConnection | None = None,
        policy_blocker: PolicyBlocker | None = None,
        policy_sources: PolicySources | None = None,
    ) -> None:
        super().__init__()
        self._settings = settings
        self._repository = repository
        self._connection = connection
        self._policy_blocker = policy_blocker
        self._policy_sources = policy_sources

    @provide(scope=Scope.APP)
    def settings(self) -> Settings:
        return self._settings

    @provide(scope=Scope.APP)
    async def engine(self, settings: Settings) -> AsyncIterator[AsyncEngine]:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        try:
            yield engine
        finally:
            await engine.dispose()

    @provide(scope=Scope.APP)
    def sessions(self, engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
        return async_sessionmaker(engine, expire_on_commit=False)

    @provide(scope=Scope.APP)
    async def broker(self, settings: Settings) -> AsyncIterator[AbstractRobustConnection]:
        if self._connection is not None:
            yield self._connection
            return
        connection = await aio_pika.connect_robust(settings.amqp_url)
        try:
            yield connection
        finally:
            await connection.close()

    @provide(scope=Scope.APP)
    def policy_blocker(self, settings: Settings) -> PolicyBlocker:
        if self._policy_blocker is not None:
            return self._policy_blocker
        client = _policy_client(settings)
        return UnconfiguredPolicyBlocker() if client is None else HttpPolicyBlocker(client)

    @provide(scope=Scope.APP)
    def policy_sources(self, settings: Settings) -> PolicySources:
        if self._policy_sources is not None:
            return self._policy_sources
        client = _policy_client(settings)
        return UnconfiguredPolicySources() if client is None else HttpPolicySources(client)

    @provide(scope=Scope.APP)
    def conversation_guard(self, settings: Settings, policy: PolicyBlocker) -> ConversationGuard:
        return ConversationGuard(
            policy,
            budget_limit=settings.conversation_budget_limit,
            repeat_multiplier=settings.deny_repeat_multiplier,
        )

    @provide(scope=Scope.REQUEST)
    async def repository(
        self, sessions: async_sessionmaker[AsyncSession]
    ) -> AsyncIterator[AuditRepository]:
        if self._repository is not None:
            yield self._repository
            return
        async with sessions() as session, session.begin():
            yield SqlAuditRepository(session)

    @provide(scope=Scope.REQUEST)
    def audit_service(self, settings: Settings, repository: AuditRepository) -> AuditService:
        return AuditService(repository, settings.deny_repeat_multiplier)

    @provide(scope=Scope.REQUEST)
    def auditor_desk(
        self,
        settings: Settings,
        journal: AuditService,
        guard: ConversationGuard,
        policy: PolicySources,
    ) -> AuditorDesk:
        return AuditorDesk(journal, guard, policy, settings.keycloak_auditor_role)


class LoginProvider(Provider):
    @provide(scope=Scope.APP)
    def jwt_verifier_settings(self, settings: Settings) -> JwtVerifierSettings:
        ssl_context = _ca_context(settings)
        return JwtVerifierSettings(
            issuer=settings.keycloak_issuer,
            audience=settings.keycloak_audience,
            client_id=settings.keycloak_client_id,
            jwks_uri=jwks_uri_from_well_known(settings.keycloak_well_known_url, ssl_context),
            ssl_context=ssl_context,
        )

    @provide(scope=Scope.APP)
    def jwt_verifier(self, settings: JwtVerifierSettings) -> JwtVerifier:
        return JwtVerifier(
            settings, PyJWKClient(settings.jwks_uri, ssl_context=settings.ssl_context)
        )

    @provide(scope=Scope.APP)
    def oidc_settings(self, settings: Settings) -> OidcSettings:
        return settings

    oidc_client = provide(OidcClient, scope=Scope.APP)

    @provide(scope=Scope.APP)
    def session_binder(
        self,
        settings: Settings,
        verifier: JwtVerifier,
        oidc: OidcClient,
        sessions: async_sessionmaker[AsyncSession],
    ) -> SessionBinder:
        return SessionBinder(
            verifier, oidc, SqlRefreshTokenStore(sessions), settings.keycloak_client_id
        )


def _ca_context(settings: Settings) -> ssl.SSLContext | None:
    if settings.tls_ca_bundle is None:
        return None
    return ssl.create_default_context(cafile=str(settings.tls_ca_bundle))


def _policy_client(settings: Settings) -> HttpPolicyClient | None:
    if not settings.policy_url or not settings.policy_api_token:
        return None
    ca = _ca_context(settings)
    return HttpPolicyClient(
        settings.policy_url,
        settings.policy_api_token,
        denied_message="",
        verify=True if ca is None else ca,
    )
