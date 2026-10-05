from __future__ import annotations

import socket
import ssl
import sys

import uvicorn

from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_sandbox_manager.app import create_app
from ads_sandbox_manager.config import load_settings, load_tls_context
from ads_sandbox_manager.egress_state_store import EgressState
from ads_sandbox_manager.lifecycle_store import CleanupWork
from ads_sandbox_manager.pair_disposal import PairDisposal
from ads_sandbox_manager.pair_retirement import PairRetirement
from ads_sandbox_manager.pair_store import PairIntent
from ads_sandbox_manager.pair_transfer import PairTransfer
from ads_sandbox_manager.store import PingProbe, SandboxSession, SessionPVC


class FailFastServer(uvicorn.Server):
    def run(self, sockets: list[socket.socket] | None = None) -> None:
        super().run(sockets=sockets)
        if not self.started:
            sys.exit(3)


def main() -> None:
    settings = load_settings()
    # TLS must be proven loadable before any network or database connection;
    # a misconfigured cert must fail the process before it reaches the store.
    load_tls_context(settings)
    listener = None
    if settings.pair_lookup is not None:
        from ads_sandbox_manager.pair_lookup import PairLookupListener

        # The CNI client pins the cluster CA and presents its own cert
        # (CN ads-ptp-cni), enforced per request. The listener serves the
        # DEDICATED pair-lookup leaf (CN ads-sandbox-manager + node IP SANs,
        # mounted from the manager-pair-lookup secret) — the main API leaf
        # carries no CN, and the plugin rejects any manager without one.
        # CERT_REQUIRED without loaded CA certs rejects every client with
        # "unknown CA" — the trust anchor must be the configured bundle.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(
            str(settings.pair_lookup_cert_path), str(settings.pair_lookup_key_path)
        )
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(settings.tls_ca_bundle))
        listener = PairLookupListener(settings, context)
        listener.start()
    try:
        prepare_schema(
            alembic_ini=alembic_ini_for("ads-sandbox-manager"),
            database_url=settings.database_url,
            tables=mapped_tables(
                SandboxSession,
                SessionPVC,
                CleanupWork,
                PingProbe,
                PairIntent,
                EgressState,
                PairRetirement,
                PairTransfer,
                PairDisposal,
            ),
        )
        FailFastServer(
            uvicorn.Config(
                create_app(settings),
                host=settings.bind_host,
                port=settings.port,
                ssl_certfile=str(settings.tls_cert_path),
                ssl_keyfile=str(settings.tls_key_path),
            )
        ).run()
    finally:
        if listener is not None:
            listener.stop()


if __name__ == "__main__":
    main()
