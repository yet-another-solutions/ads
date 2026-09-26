import hashlib
import os
import sqlite3
from dataclasses import replace
from uuid import uuid4

import pytest

from ads_sandbox_egress.identity_store import IdentityStore, StateIdentity, StateUnavailable


@pytest.fixture
def custody(tmp_path):
    tmp_path.chmod(0o700)
    key = os.urandom(32)
    identity = StateIdentity(
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        str(uuid4()),
        str(uuid4()),
        hashlib.sha256(key).hexdigest(),
    )
    return tmp_path, identity, key


def open_store(custody, **kwargs):
    return IdentityStore(*custody, capacity=2**20, **kwargs)


def test_encrypted_identity_continuity_and_no_reinitialization(custody):
    secret = b"test-private-material-" * 100
    store = open_store(custody, create=True)
    store.prepare_key("root-v1", "root", b"root-public", secret)
    store.close()
    assert secret not in (custody[0] / "identity.sqlite").read_bytes()
    recovered = open_store(custody)
    assert recovered.key("root-v1")[2] == secret
    recovered.prepare_key("root-v1", "root", b"root-public", secret)
    with pytest.raises(StateUnavailable, match="conflict"):
        recovered.prepare_key("root-v1", "root", b"root-public", b"different")
    with pytest.raises(StateUnavailable, match="rotation"):
        recovered.prepare_key("root-v2", "root", b"root-public", b"different")
    recovered.close()
    with pytest.raises(StateUnavailable, match="refusing initialization"):
        open_store(custody, create=True)


def test_single_local_owner_and_missing_retained_state(custody):
    with pytest.raises(FileNotFoundError):
        open_store(custody)
    store = open_store(custody, create=True)
    try:
        with pytest.raises(BlockingIOError):
            open_store(custody)
    finally:
        store.close()


def test_wrong_identity_wrapping_or_authenticated_content_fails(custody):
    store = open_store(custody, create=True)
    store.prepare_key("root-v1", "root", b"public", b"private")
    store.close()
    path, identity, key = custody
    with pytest.raises(StateUnavailable):
        open_store((path, replace(identity, pvc_uid=str(uuid4())), key))
    with pytest.raises(StateUnavailable):
        open_store((path, identity, os.urandom(32)))
    with sqlite3.connect(path / "identity.sqlite") as db:
        db.execute("UPDATE keys SET sealed=randomblob(40)")
    with pytest.raises(StateUnavailable, match="authentication"):
        open_store(custody)


def test_publication_before_dependency_retirement(custody):
    store = open_store(custody, create=True)
    try:
        store.prepare_key("ech/one", "ech", b"configuration", b"private")
        with pytest.raises(StateUnavailable, match="unpublished"):
            store.commit_publication("answer/one", b"records", ("ech/one",), 1000)
        store.advance("ech/one", "prepared", "published")
        store.commit_publication("answer/one", b"records", ("ech/one",), 1000)
        store.commit_publication("answer/one", b"records", ("ech/one",), 1000)
        store.advance("ech/one", "published", "active")
        store.advance("ech/one", "active", "retiring")
        with pytest.raises(StateUnavailable, match="live publication"):
            store.retire("ech/one", now=1000)
        store.retire("ech/one", now=1001)
        with pytest.raises(StateUnavailable):
            store.key("ech/one")
    finally:
        store.close()


def test_quota_never_evicts_existing_key(custody):
    store = IdentityStore(*custody, capacity=65536, create=True)
    try:
        store.prepare_key("root", "root", b"public", b"private")
        with pytest.raises(StateUnavailable, match="quota"):
            store.prepare_key("large", "ech", b"a" * 65536, b"b" * 65536)
        assert store.key("root")[2] == b"private"
    finally:
        store.close()


def test_public_key_substitution_is_authenticated(custody):
    store = open_store(custody, create=True)
    store.prepare_key("ech", "ech", b"original-config", b"private")
    store.close()
    with sqlite3.connect(custody[0] / "identity.sqlite") as db:
        db.execute("UPDATE keys SET public=?", (b"substituted-config",))
    with pytest.raises(StateUnavailable, match="authentication"):
        open_store(custody)


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE publications SET retain_until=1",
        "DELETE FROM dependencies",
        "UPDATE keys SET stage='retiring'",
        "DELETE FROM keys",
    ],
)
def test_publication_metadata_and_missing_keys_cannot_bypass_retention(custody, mutation):
    store = open_store(custody, create=True)
    store.prepare_key("ech", "ech", b"configuration", b"private")
    store.advance("ech", "prepared", "published")
    store.commit_publication("answer", b"wire", ("ech",), 1000)
    store.close()
    with sqlite3.connect(custody[0] / "identity.sqlite") as db:
        db.execute(mutation)
    with pytest.raises(StateUnavailable, match="authentication"):
        open_store(custody)


def test_directory_name_cannot_change_sqlite_uri_parameters(custody):
    directory = custody[0] / "state?mode=memory#fragment"
    directory.mkdir(mode=0o700)
    changed = directory, custody[1], custody[2]
    store = open_store(changed, create=True)
    store.prepare_key("root", "root", b"public", b"private")
    store.close()
    assert (directory / "identity.sqlite").stat().st_size > 0
    recovered = open_store(changed)
    try:
        assert recovered.key("root")[2] == b"private"
    finally:
        recovered.close()


def test_foreign_permissions_and_symlink_never_adopted(custody):
    directory, _, _ = custody
    directory.chmod(0o755)
    with pytest.raises(StateUnavailable, match="private owned"):
        open_store(custody, create=True)
    directory.chmod(0o700)
    target = directory / "outside"
    target.write_bytes(b"do not touch")
    target.chmod(0o600)
    (directory / "identity.sqlite").symlink_to(target)
    with pytest.raises(StateUnavailable, match="unsafe retained"):
        open_store(custody)
    assert target.read_bytes() == b"do not touch"
