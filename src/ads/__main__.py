from __future__ import annotations

import uvicorn

from ads.app import create_app
from ads.config import load_settings


def main() -> None:
    settings = load_settings()
    ssl_certfile = str(settings.tls_cert_path) if settings.tls_enabled else None
    ssl_keyfile = str(settings.tls_key_path) if settings.tls_enabled else None
    uvicorn.run(
        create_app(settings),
        host=settings.bind_host,
        port=settings.port,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )


if __name__ == "__main__":
    main()
