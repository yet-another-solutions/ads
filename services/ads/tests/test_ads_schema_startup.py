from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from ads.models import ChatSession, Project, SessionEntry, SessionRun, SessionRunBuffer
from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema


def test_prepare_schema_creates_threadline_tables(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'ads.db'}"
    tables = mapped_tables(Project, ChatSession, SessionEntry, SessionRun, SessionRunBuffer)
    prepare_schema(
        alembic_ini=alembic_ini_for("ads"),
        database_url=database_url,
        tables=tables,
    )
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        for table in tables:
            assert inspector.has_table(table.name)
    finally:
        engine.dispose()
