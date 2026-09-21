from __future__ import annotations

import os
import sys
from pathlib import Path
from uuid import UUID

from ads_sandbox_ca.certificates import mint
from ads_sandbox_ca.devices import mounted_outputs
from ads_sandbox_ca.outputs import write_outputs


def read_input(path: Path) -> bytes:
    with path.open("rb") as stream:
        value = stream.read(4 * 1024 * 1024 + 1)
    if len(value) > 4 * 1024 * 1024:
        raise ValueError("CA input exceeds size limit")
    return value


def initialize() -> None:
    os.umask(0o077)
    attempt = UUID(os.environ["ADS_CA_ATTEMPT"])
    size = int(os.environ["ADS_CA_BYTES"])
    material = mint(
        read_input(Path("/signer/tls.crt")),
        read_input(Path("/signer/tls.key")),
        read_input(Path("/additional/ca.crt")),
    )
    with mounted_outputs(size) as (public, private):
        write_outputs(public, private, material, attempt)
    print("ads-sandbox-ca: paired outputs complete and unmounted", flush=True)


def main() -> None:
    try:
        initialize()
    except Exception as error:
        # Do not render exception values, PEM content, environment or signer paths.
        print(f"ads-sandbox-ca: initialization failed ({type(error).__name__})", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
