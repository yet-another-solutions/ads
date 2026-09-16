from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, text

from ads_commons_schema import (
    SchemaMismatchError,
    alembic_ini_for,
    prepare_schema,
    validate_schema,
)

_MINIMAL_INI = """[alembic]
script_location = alembic
version_path_separator = os

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""

_ENV_PY = """
from __future__ import annotations

from alembic import context
from sqlalchemy import Column, Integer, MetaData, String, Table, engine_from_config, pool

target_metadata = MetaData()
Table(
    "item",
    target_metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String(32), nullable=False),
)

config = context.config


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
"""

_VERSION = """
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_item"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "item",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(32), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("item")
"""


def _item_metadata() -> MetaData:
    metadata = MetaData()
    Table(
        "item",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("name", String(32), nullable=False),
    )
    return metadata


def _write_alembic(root: Path) -> Path:
    versions = root / "alembic" / "versions"
    versions.mkdir(parents=True)
    (root / "alembic.ini").write_text(_MINIMAL_INI)
    (root / "alembic" / "env.py").write_text(_ENV_PY)
    (versions / "0001_item.py").write_text(_VERSION)
    return root / "alembic.ini"


def test_prepare_schema_upgrades_and_matches(tmp_path: Path) -> None:
    alembic_ini = _write_alembic(tmp_path)
    database_url = f"sqlite:///{tmp_path / 'schema.db'}"
    prepare_schema(
        alembic_ini=alembic_ini,
        database_url=database_url,
        tables=_item_metadata().sorted_tables,
    )
    engine = create_engine(database_url)
    try:
        validate_schema(engine, _item_metadata().sorted_tables)
    finally:
        engine.dispose()


def test_validate_schema_fails_when_table_missing(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'empty.db'}"
    engine = create_engine(database_url)
    try:
        with pytest.raises(SchemaMismatchError, match="missing table item"):
            validate_schema(engine, _item_metadata().sorted_tables)
    finally:
        engine.dispose()


def test_validate_schema_fails_when_column_missing(tmp_path: Path) -> None:
    alembic_ini = _write_alembic(tmp_path)
    database_url = f"sqlite:///{tmp_path / 'partial.db'}"
    prepare_schema(
        alembic_ini=alembic_ini,
        database_url=database_url,
        tables=_item_metadata().sorted_tables,
    )
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE item DROP COLUMN name"))
        with pytest.raises(SchemaMismatchError, match="missing column item.name"):
            validate_schema(engine, _item_metadata().sorted_tables)
    finally:
        engine.dispose()


def test_alembic_ini_for_uses_cwd_services(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ini = tmp_path / "services" / "ads" / "alembic.ini"
    ini.parent.mkdir(parents=True)
    ini.write_text("[alembic]\n")
    monkeypatch.chdir(tmp_path)
    assert alembic_ini_for("ads") == ini


def test_alembic_ini_for_missing_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="alembic.ini not found for ads"):
        alembic_ini_for("ads")
