from __future__ import annotations

import os

BUILD_ENV = "ADS_BUILD"
UNRELEASED_BUILD = "dev"


def identity(service: str) -> str:
    return f"{service} {os.environ.get(BUILD_ENV, '').strip() or UNRELEASED_BUILD}"
