from __future__ import annotations

import pytest

from sandbox_fixtures import (  # noqa: F401
    harness,
    long_harness,
    sandbox_database_url,
    sandbox_engine,
    sandbox_settings,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
