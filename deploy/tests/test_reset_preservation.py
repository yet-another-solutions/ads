from __future__ import annotations

import importlib.util
import os
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

ROOT = Path(__file__).parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "deploy" / "reset" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


protected = load("protected")
models = load("models")


@pytest.fixture
def store(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    key = directory / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    value = protected.ProtectedStore(directory, source_root=ROOT)
    yield value
    value.close()


@pytest.fixture
def rows():
    now = datetime.now(UTC).isoformat()
    return [
        {
            "id": str(uuid4()),
            "user_id": str(uuid4()),
            "description": "Synthetic restoration fixture",
            "name": "fixture",
            "type": "openai-stream",
            "url": "https://fixture.invalid/v1",
            "authentication": {"openai-bearer": {"token": "synthetic-sensitive"}},
            "options": {"model-name": "glm-5.3", "max_context_tokens": 4096},
            "created_at": now,
            "updated_at": now,
        }
    ]


def test_encrypted_backup_roundtrip_refresh_and_empty_source_protection(store, rows):
    assert models.refresh_backup(store, rows) == rows
    raw = (store.path / "models").read_bytes()
    assert b"synthetic-sensitive" not in raw and b"fixture.invalid" not in raw
    assert models.refresh_backup(store, []) == rows
    rows[0]["authentication"]["openai-bearer"]["token"] = "rotated-sensitive"
    assert models.refresh_backup(store, rows) == rows
    assert (store.path / "models").read_bytes() != raw
    assert models.refresh_backup(store, []) == rows


def test_empty_source_without_external_backup_cannot_proceed(store):
    with pytest.raises(protected.PreservationError):
        models.refresh_backup(store, [])
    assert not (store.path / "models").exists()


@pytest.mark.parametrize("fault", ["mode", "symlink", "tamper", "wrong-domain"])
def test_backup_permission_identity_and_encryption_fail_closed(store, rows, fault):
    models.refresh_backup(store, rows)
    path = store.path / "models"
    if fault == "mode":
        path.chmod(0o644)
    elif fault == "symlink":
        other = store.path / "elsewhere"
        path.rename(other)
        path.symlink_to(other)
    elif fault == "tamper":
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
    else:
        store.write("checkpoint", {"not": "models"})
        path.write_bytes((store.path / "checkpoint").read_bytes())
    with pytest.raises(protected.PreservationError) as error:
        models.refresh_backup(store, [])
    assert "synthetic-sensitive" not in str(error.value)


def test_private_store_lock_excludes_another_reset(store):
    another = protected.ProtectedStore(store.path, source_root=ROOT)
    try:
        with store.lock(), pytest.raises(protected.PreservationError, match="another"):
            with another.lock():
                pytest.fail("concurrent reset lock admitted")
        with another.lock():
            pass
    finally:
        another.close()


@pytest.mark.parametrize("fault", ["owner", "token", "field", "duplicate"])
def test_full_owner_and_authentication_payload_required(rows, fault):
    if fault == "owner":
        rows[0]["user_id"] = ""
    elif fault == "token":
        rows[0]["authentication"]["openai-bearer"]["token"] = ""
    elif fault == "field":
        del rows[0]["options"]
    else:
        rows.append(deepcopy(rows[0]))
    with pytest.raises(protected.PreservationError):
        models.validate_models(rows)


class Api:
    def __init__(self, owner):
        self.owner, self.records, self.calls, self.fail, self.lost = owner, [], [], False, False

    def models(self, owner):
        assert owner == self.owner
        return deepcopy(self.records)

    def create(self, owner, payload):
        assert owner == self.owner
        self.calls.append("create")
        if self.fail:
            raise RuntimeError("synthetic-sensitive upstream body")
        result = {"id": str(uuid4()), **deepcopy(payload)}
        self.records.append(result)
        if self.lost:
            self.lost = False
            raise TimeoutError("lost successful create reply")
        return deepcopy(result)

    def model(self, owner, model_id):
        assert owner == self.owner
        return deepcopy(next(row for row in self.records if row["id"] == model_id))

    def invoke(self, owner, model_id):
        assert owner == self.owner
        self.calls.append("invoke")


def test_supported_restore_preserves_owner_full_auth_and_handles_generated_ids(rows):
    api = Api(rows[0]["user_id"])
    mapping = models.restore_models(rows, api, invoke=True)
    assert mapping[rows[0]["id"]] != rows[0]["id"]
    assert models.restore_models(rows, api, invoke=True) == mapping
    assert api.calls == ["create", "invoke", "invoke"]
    assert api.records[0]["authentication"] == rows[0]["authentication"]


def test_lost_restore_reply_is_idempotent_and_conflicting_records_block(rows):
    api = Api(rows[0]["user_id"])
    api.lost = True
    with pytest.raises(protected.PreservationError):
        models.restore_models(rows, api, invoke=True)
    assert api.calls == ["create"]
    models.restore_models(rows, api, invoke=True)
    assert api.calls == ["create", "invoke"]
    api.records[0]["description"] = "conflicting owner change"
    with pytest.raises(protected.PreservationError):
        models.restore_models(rows, api, invoke=True)
    assert api.calls == ["create", "invoke"]


def test_restore_failure_sanitizes_errors_and_never_invokes_provider(rows):
    api = Api(rows[0]["user_id"])
    api.fail = True
    with pytest.raises(protected.PreservationError) as error:
        models.restore_models(rows, api, invoke=True)
    assert "synthetic-sensitive" not in str(error.value) and api.calls == ["create"]
