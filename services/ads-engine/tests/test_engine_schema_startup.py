from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_engine.store import ActiveSessionRow


def test_prepare_schema_creates_active_sessions(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'engine.db'}"
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-engine"),
        database_url=database_url,
        tables=mapped_tables(ActiveSessionRow),
    )
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert inspector.has_table("active_sessions")
        columns = {column["name"] for column in inspector.get_columns("active_sessions")}
        assert columns == {"session_id", "message_id"}
    finally:
        engine.dispose()
