from __future__ import annotations

from typing import Any

from advanced_alchemy.base import AdvancedDeclarativeBase, CommonTableAttributes
from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool


class Base(CommonTableAttributes, AdvancedDeclarativeBase):
    __abstract__ = True


def create_db_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        kwargs: dict[str, Any] = {"connect_args": {"check_same_thread": False}}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
        return create_engine(url, **kwargs)
    return create_engine(url)
