from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, inspect

from ads_commons_schema import alembic_ini_for, mapped_tables, prepare_schema
from ads_preferences.models import UserModel


def test_prepare_schema_creates_user_model(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'preferences.db'}"
    prepare_schema(
        alembic_ini=alembic_ini_for("ads-preferences"),
        database_url=database_url,
        tables=mapped_tables(UserModel),
    )
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert inspector.has_table("user_model")
        columns = {column["name"] for column in inspector.get_columns("user_model")}
        assert "options" in columns
        assert "authentication" in columns
    finally:
        engine.dispose()
