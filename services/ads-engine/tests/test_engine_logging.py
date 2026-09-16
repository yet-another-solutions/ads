from __future__ import annotations

from pathlib import Path

import pytest
import structlog

from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_engine.logconfig import configure_logging
from ads_engine.store import ActiveSessionRow


def test_engine_info_logs_survive_prepare_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    configure_logging()
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-engine"),
        database_url=f"sqlite:///{tmp_path / 'engine.db'}",
        tables=mapped_tables(ActiveSessionRow),
    )
    configure_logging()
    structlog.get_logger("ads_engine").info(
        "ads_engine_started",
        request_topic="ads.engine.request",
        output_topic="ads.engine.output",
    )
    captured = capsys.readouterr()
    text = captured.err + captured.out
    assert "ads_engine_started" in text
    assert "ads.engine.request" in text
