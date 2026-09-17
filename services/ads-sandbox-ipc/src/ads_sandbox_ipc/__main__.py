from __future__ import annotations

import socket
import sys

import uvicorn

from ads_sandbox_ipc.app import create_app
from ads_sandbox_ipc.config import load_settings


class FailFastServer(uvicorn.Server):
    def run(self, sockets: list[socket.socket] | None = None) -> None:
        super().run(sockets=sockets)
        if not self.started:
            sys.exit(3)


def main() -> None:
    settings = load_settings()  # Validate cert, key, and CA on the main thread, before I/O.
    FailFastServer(
        uvicorn.Config(
            create_app(settings),
            host=settings.bind_host,
            port=settings.port,
            ssl_certfile=str(settings.tls_cert_path),
            ssl_keyfile=str(settings.tls_key_path),
        )
    ).run()


if __name__ == "__main__":
    main()
