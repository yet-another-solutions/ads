"""Exact application-table reset; preserve schema, role and grant identities."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from protected import PreservationError
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool

from ads_commons_schema import prepare_schema

MODULES = {
    "ads": ("ads.db", "ads.models"),
    "ads-preferences": ("ads_preferences.db", "ads_preferences.models"),
    "ads-engine": ("ads_engine.store",),
    "ads-sandbox-mcp": ("ads_sandbox_mcp.store",),
    "ads-sandbox-manager": (
        "ads_sandbox_manager.store",
        "ads_sandbox_manager.lifecycle_store",
        "ads_sandbox_manager.pair_store",
        "ads_sandbox_manager.egress_state_store",
        "ads_sandbox_manager.pair_retirement",
        "ads_sandbox_manager.pair_transfer",
        "ads_sandbox_manager.pair_disposal",
    ),
}


def application_tables(service: str):
    if service not in MODULES:
        raise PreservationError("reset service is outside the explicit ADS application scope")
    modules = [importlib.import_module(name) for name in MODULES[service]]
    bases = {module.Base for module in modules if hasattr(module, "Base")}
    if len(bases) != 1:
        raise PreservationError("normal application schema metadata unavailable")
    return tuple(next(iter(bases)).metadata.tables.values())


@dataclass(frozen=True)
class Target:
    service: str
    database: str
    owner: str
    url: str = field(repr=False)
    schema: str = "public"

    def __post_init__(self):
        if (
            self.service not in MODULES
            or self.schema != "public"
            or not self.database.strip()
            or not self.owner.strip()
        ):
            raise PreservationError("explicit supported database/schema/owner required")


def serial(value: Any) -> Any:
    if isinstance(value, (UUID, datetime)):
        return str(value) if isinstance(value, UUID) else value.isoformat()
    if isinstance(value, dict):
        return {key: serial(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [serial(item) for item in value]
    return value


class Database:
    def __init__(self, target: Target, root: Path):
        self.target, self.root = target, root
        self.tables = application_tables(target.service)
        self.allowed = {table.name for table in self.tables} | {"alembic_version"}
        self.engine = create_engine(
            target.url, echo=False, hide_parameters=True, poolclass=NullPool
        )
        if self.engine.dialect.name != "postgresql":
            raise PreservationError("reset requires PostgreSQL")

    def close(self):
        self.engine.dispose()

    def _inventory(self, db) -> dict[str, Any]:
        identity = db.execute(
            text(
                "SELECT current_database(), current_user, "
                "(SELECT oid FROM pg_database WHERE datname=current_database())"
            )
        ).one()
        if identity[0] != self.target.database or identity[1] != self.target.owner:
            raise PreservationError("connected reset database or role differs from explicit scope")
        schema = db.execute(
            text(
                "SELECT oid, pg_get_userbyid(nspowner), nspacl::text "
                "FROM pg_namespace WHERE nspname=:schema"
            ),
            {"schema": self.target.schema},
        ).one()
        rows = db.execute(
            text(
                "SELECT c.relname, c.relkind, pg_get_userbyid(c.relowner), c.relacl::text, "
                "c.relispartition FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname=:schema AND c.relkind NOT IN ('i','I','t') ORDER BY c.relname"
            ),
            {"schema": self.target.schema},
        ).all()
        if any(
            name not in self.allowed or kind != "r" or owner != self.target.owner or partition
            for name, kind, owner, acl, partition in rows
        ):
            raise PreservationError("unknown, shared, partitioned or non-table schema object")
        routines = db.scalar(
            text(
                "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
                "WHERE n.nspname=:schema"
            ),
            {"schema": self.target.schema},
        )
        if routines:
            raise PreservationError("schema contains routines outside reset table scope")
        types = db.scalar(
            text(
                "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace "
                "WHERE n.nspname=:schema AND t.typtype IN ('d','e','r','m')"
            ),
            {"schema": self.target.schema},
        )
        if types:
            raise PreservationError("schema contains custom types outside reset table scope")
        column_acl = db.scalar(
            text(
                "SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid "
                "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=:schema "
                "AND a.attacl IS NOT NULL"
            ),
            {"schema": self.target.schema},
        )
        if column_acl:
            raise PreservationError("column-specific grants require a separate scoped reset plan")
        grants = [
            dict(row)
            for row in db.execute(
                text(
                    "SELECT c.relname AS name, CASE WHEN a.grantee=0 THEN 'PUBLIC' "
                    "ELSE pg_get_userbyid(a.grantee) END AS grantee, "
                    "pg_get_userbyid(a.grantor) AS grantor, a.privilege_type AS privilege, "
                    "a.is_grantable AS grantable FROM pg_class c "
                    "JOIN pg_namespace n ON n.oid=c.relnamespace "
                    "CROSS JOIN LATERAL aclexplode(c.relacl) a "
                    "WHERE n.nspname=:schema AND c.relkind='r' "
                    "ORDER BY c.relname, a.grantee, a.privilege_type"
                ),
                {"schema": self.target.schema},
            ).mappings()
        ]
        if any(row["grantor"] != self.target.owner for row in grants):
            raise PreservationError("third-party grantor requires a separate scoped reset plan")
        return {
            "service": self.target.service,
            "database": identity[0],
            "database_oid": identity[2],
            "role": identity[1],
            "schema": self.target.schema,
            "schema_oid": schema[0],
            "schema_owner": schema[1],
            "schema_acl": schema[2],
            "grants": grants,
            "tables": [
                {"name": name, "owner": owner, "acl": acl} for name, _, owner, acl, _ in rows
            ],
        }

    def inventory(self) -> dict[str, Any]:
        try:
            with self.engine.begin() as db:
                return self._inventory(db)
        except Exception:
            raise PreservationError("application database scope verification failed") from None

    def models(self) -> list[dict[str, Any]]:
        if self.target.service != "ads-preferences":
            raise PreservationError("model backup requires the explicit preferences database")
        try:
            with self.engine.begin() as db:
                self._inventory(db)
                return [
                    serial(dict(row))
                    for row in db.execute(
                        text("SELECT * FROM public.user_model ORDER BY id")
                    ).mappings()
                ]
        except Exception:
            raise PreservationError("full model backup read failed") from None

    def associations(self) -> dict[str, Any]:
        if self.target.service not in ("ads-sandbox-manager", "ads-sandbox-mcp"):
            return {}
        try:
            with self.engine.begin() as db:
                inventory = self._inventory(db)
                quote = self.engine.dialect.identifier_preparer.quote
                return {
                    item["name"]: [
                        serial(dict(row))
                        for row in db.execute(
                            text(f"SELECT * FROM public.{quote(item['name'])}")
                        ).mappings()
                    ]
                    for item in inventory["tables"]
                    if item["name"] != "alembic_version"
                }
        except Exception:
            raise PreservationError("original runtime association backup failed") from None

    def reset(self, captured: dict[str, Any]) -> None:
        """One transaction; RESTRICT is the final cross-scope dependency fence.

        The schema itself stays intact to preserve its owner/ACL. All explicitly
        authorized application tables, including Alembic's version ledger, are
        dropped together and recreated by normal initialization. This is not
        TRUNCATE, an old-schema migration, or unchecked DROP SCHEMA CASCADE.
        """
        try:
            with self.engine.begin() as db:
                db.execute(text("SET LOCAL lock_timeout='5s'"))
                db.execute(text("SET LOCAL statement_timeout='30s'"))
                current = self._inventory(db)
                if {k: v for k, v in current.items() if k not in ("tables", "grants")} != {
                    k: v for k, v in captured.items() if k not in ("tables", "grants")
                }:
                    raise PreservationError("original database or schema identity changed")
                # Restart after a lost successful DROP may see an empty schema.
                # Anything else must remain the original captured table scope.
                if current["tables"] and (
                    current["tables"] != captured["tables"]
                    or current["grants"] != captured["grants"]
                ):
                    raise PreservationError("captured application table scope changed")
                others = db.scalar(
                    text(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                        "AND pid<>pg_backend_pid() AND backend_type='client backend'"
                    )
                )
                if others:
                    raise PreservationError("application database still has connected writers")
                if current["tables"]:
                    quote = self.engine.dialect.identifier_preparer.quote
                    names = ", ".join("public." + quote(item["name"]) for item in current["tables"])
                    db.execute(text("DROP TABLE " + names + " RESTRICT"))
                if self._inventory(db)["tables"]:
                    raise PreservationError("fresh schema still contains application tables")
        except Exception:
            raise PreservationError(
                "scoped reset refused or rolled back; keep writers fenced"
            ) from None

    def initialize(self, captured: dict[str, Any]) -> None:
        try:
            prepare_schema(
                alembic_ini=self.root / "services" / self.target.service / "alembic.ini",
                database_url=self.target.url,
                tables=self.tables,
            )
            with self.engine.begin() as db:
                current = self._inventory(db)
                quote = self.engine.dialect.identifier_preparer.quote
                present = {item["name"] for item in current["tables"]}
                allowed = {
                    "SELECT",
                    "INSERT",
                    "UPDATE",
                    "DELETE",
                    "TRUNCATE",
                    "REFERENCES",
                    "TRIGGER",
                    "MAINTAIN",
                }
                for grant in captured["grants"]:
                    if grant["name"] not in present or grant["privilege"] not in allowed:
                        raise PreservationError("original table grant cannot be restored")
                    grantee = "PUBLIC" if grant["grantee"] == "PUBLIC" else quote(grant["grantee"])
                    db.execute(
                        text(
                            "GRANT "
                            + grant["privilege"]
                            + " ON TABLE public."
                            + quote(grant["name"])
                            + " TO "
                            + grantee
                            + (" WITH GRANT OPTION" if grant["grantable"] else "")
                        )
                    )
                restored = self._inventory(db)
                if restored["grants"] != captured["grants"]:
                    raise PreservationError("original table grants differ after initialization")
                for key in ("database_oid", "role", "schema_oid", "schema_owner", "schema_acl"):
                    if restored[key] != captured[key]:
                        raise PreservationError("database/schema grant identity changed")
        except Exception:
            raise PreservationError(
                "normal fresh-schema initialization failed; keep writers fenced"
            ) from None
