from pathlib import Path

import pytest
import structlog
from structlog.testing import LogCapture

from ads_sandbox_ipc import controller, service
from ipc_support import Harness


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def ipc(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


@pytest.fixture
def ipc_logs(monkeypatch):
    capture = LogCapture()
    logger = structlog.wrap_logger(
        structlog.ReturnLogger(), processors=[capture], cache_logger_on_first_use=False
    )
    monkeypatch.setattr(controller, "log", logger)
    monkeypatch.setattr(service, "log", logger)
    return capture.entries
