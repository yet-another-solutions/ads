from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, Table, create_engine, inspect


class SchemaMismatchError(RuntimeError):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("database schema does not match models: " + "; ".join(problems))


def alembic_ini_for(service: str) -> Path:
    candidates = (
        Path.cwd() / "services" / service / "alembic.ini",
        Path("/app/services") / service / "alembic.ini",
    )
    for path in candidates:
        if path.is_file():
            return path
    raise RuntimeError(f"alembic.ini not found for {service}")


def mapped_tables(*models: type[Any]) -> tuple[Table, ...]:
    tables: list[Table] = []
    for model in models:
        table = getattr(model, "__table__", None)
        if not isinstance(table, Table):
            raise TypeError(f"{model} is not a mapped class")
        tables.append(table)
    return tuple(tables)


def upgrade_head(*, alembic_ini: Path, database_url: str) -> None:
    if not alembic_ini.is_file():
        raise RuntimeError(f"alembic.ini not found: {alembic_ini}")
    config = Config(str(alembic_ini))
    config.set_main_option("script_location", str(alembic_ini.parent / "alembic"))
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    config.set_main_option("path_separator", "os")
    command.upgrade(config, "head")


def validate_schema(engine: Engine, tables: Sequence[Table]) -> None:
    inspector = inspect(engine)
    present = set(inspector.get_table_names())
    problems: list[str] = []
    for table in tables:
        if table.name not in present:
            problems.append(f"missing table {table.name}")
            continue
        columns = {column["name"] for column in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name not in columns:
                problems.append(f"missing column {table.name}.{column.name}")
    if problems:
        raise SchemaMismatchError(problems)


def prepare_schema(*, alembic_ini: Path, database_url: str, tables: Sequence[Table]) -> None:
    upgrade_head(alembic_ini=alembic_ini, database_url=database_url)
    engine = _engine_for(database_url)
    try:
        validate_schema(engine, tables)
    finally:
        engine.dispose()


def _engine_for(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        return create_engine(database_url, connect_args={"check_same_thread": False})
    return create_engine(database_url)
