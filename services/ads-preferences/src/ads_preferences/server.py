from __future__ import annotations

import socket
import sys

import uvicorn

from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_preferences.app import create_app
from ads_preferences.config import Settings, load_settings, load_tls_context
from ads_preferences.models import ProjectEgress, UserModel

STARTUP_FAILURE = 3


class FailFastServer(uvicorn.Server):
    def run(self, sockets: list[socket.socket] | None = None) -> None:
        super().run(sockets=sockets)
        if not self.started:
            sys.exit(STARTUP_FAILURE)


def run(settings: Settings | None = None) -> None:
    loaded = settings if settings is not None else load_settings()
    load_tls_context(loaded)
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-preferences"),
        database_url=loaded.database_url,
        tables=mapped_tables(UserModel, ProjectEgress),
    )
    config = uvicorn.Config(
        create_app(loaded),
        host=loaded.bind_host,
        port=loaded.port,
        ssl_certfile=str(loaded.tls_cert_path),
        ssl_keyfile=str(loaded.tls_key_path),
    )
    FailFastServer(config).run()
