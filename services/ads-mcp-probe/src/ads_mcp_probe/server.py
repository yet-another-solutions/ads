from __future__ import annotations

import socket
import sys

import uvicorn

from ads_mcp_probe.app import create_app
from ads_mcp_probe.config import Settings, load_settings

STARTUP_FAILURE = 3


class FailFastServer(uvicorn.Server):
    def run(self, sockets: list[socket.socket] | None = None) -> None:
        super().run(sockets=sockets)
        if not self.started:
            sys.exit(STARTUP_FAILURE)


def run(settings: Settings | None = None) -> None:
    loaded = settings if settings is not None else load_settings()
    config = uvicorn.Config(
        create_app(),
        host=loaded.bind_host,
        port=loaded.port,
        ssl_certfile=str(loaded.tls_cert_path),
        ssl_keyfile=str(loaded.tls_key_path),
    )
    FailFastServer(config).run()
