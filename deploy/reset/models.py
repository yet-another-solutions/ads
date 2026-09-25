"""Full owner-associated model preservation and supported-API restoration."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

import msgspec
from protected import PreservationError, ProtectedStore

from ads_commons.preferences import ModelWrite

PAYLOAD = ("description", "name", "type", "url", "authentication", "options")
FIELDS = {"id", "user_id", *PAYLOAD, "created_at", "updated_at"}


def validate_models(rows: object) -> list[dict[str, Any]]:
    try:
        if not isinstance(rows, list) or not rows:
            raise ValueError
        result, ids, identities = [], set(), set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != FIELDS:
                raise ValueError
            for key in ("id", "user_id"):
                if not isinstance(row[key], str) or str(UUID(row[key])) != row[key]:
                    raise ValueError
            for key in ("created_at", "updated_at"):
                if datetime.fromisoformat(row[key]).tzinfo is None:
                    raise ValueError
            # The production DTO validates the actual auth shape, not a masked
            # list response. No serialized credential enters an error message.
            payload = {key: row[key] for key in PAYLOAD}
            parsed = msgspec.convert(payload, type=ModelWrite, strict=True)
            if not parsed.authentication.openai_bearer.token.strip():
                raise ValueError
            identity = row["user_id"], row["type"], row["url"], row["name"]
            if row["id"] in ids or identity in identities:
                raise ValueError
            ids.add(row["id"])
            identities.add(identity)
            result.append(deepcopy(row))
        return result
    except Exception:
        raise PreservationError("nonempty complete model and owner backup required") from None


def refresh_backup(store: ProtectedStore, rows: object) -> list[dict[str, Any]]:
    """Never overwrite a verified nonempty recovery copy with empty reset data."""
    if rows == []:
        try:
            return validate_models(store.read("models"))
        except Exception:
            raise PreservationError("empty source has no verified recovery backup") from None
    checked = validate_models(rows)
    store.write("models", checked)
    return validate_models(store.read("models"))


class OwnerModels(Protocol):
    def models(self, owner: str) -> list[dict[str, Any]]: ...
    def create(self, owner: str, payload: dict[str, Any]) -> dict[str, Any]: ...
    def model(self, owner: str, model_id: str) -> dict[str, Any]: ...
    def invoke(self, owner: str, model_id: str) -> None: ...


def restore_models(rows: object, api: OwnerModels, *, invoke: bool) -> dict[str, str]:
    """Idempotent across regenerated IDs and ambiguous successful POST replies.

    Each concrete API call must obtain fresh owner-correct authorization. A
    matching logical model with changed metadata/auth is a conflict, not a
    reason to overwrite another credential or create another model.
    """
    backup = validate_models(rows)
    mapping = {}
    try:
        for row in backup:
            owner = row["user_id"]
            payload = {key: row[key] for key in PAYLOAD}
            existing = api.models(owner)
            matches = [
                model
                for model in existing
                if model["id"] == row["id"]
                or all(model[key] == row[key] for key in ("name", "type", "url"))
            ]
            if len(matches) > 1 or (
                matches and {key: matches[0][key] for key in PAYLOAD} != payload
            ):
                raise PreservationError("existing owner model conflicts with protected backup")
            chosen = matches[0] if matches else api.create(owner, payload)
            actual = api.model(owner, chosen["id"])
            if {key: actual[key] for key in PAYLOAD} != payload:
                raise PreservationError("restored model verification failed")
            mapping[row["id"]] = actual["id"]
        if invoke:
            for row in backup:
                api.invoke(row["user_id"], mapping[row["id"]])
        return mapping
    except Exception:
        raise PreservationError("owner-correct model restoration or validation failed") from None
