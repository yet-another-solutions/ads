import sqlite3

import pytest

from ads_sandbox_egress.identity_store import StateUnavailable
from ads_sandbox_egress.runtime_identity import root_identity
from test_identity_store import custody as custody
from test_identity_store import open_store


def test_root_published_before_return_and_stable_recovery(custody):
    state = open_store(custody, create=True)
    try:
        root = root_identity(state, initial=True)
        assert root.stage == "active"
        assert state.publication_head("root-anchor/") is not None
        with pytest.raises(StateUnavailable):
            root_identity(state, initial=True)
    finally:
        state.close()
    state = open_store(custody)
    try:
        recovered = root_identity(state, initial=False)
        assert recovered.fingerprint == root.fingerprint
        assert recovered.private_key.private_bytes_raw() == root.private_key.private_bytes_raw()
    finally:
        state.close()


def test_missing_publication_never_reinitializes(custody):
    state = open_store(custody, create=True)
    try:
        with pytest.raises(StateUnavailable, match="publication missing"):
            root_identity(state, initial=False)
        assert state.key_names("root") == ()
    finally:
        state.close()


def test_authenticated_root_publication_cannot_be_replaced(custody):
    state = open_store(custody, create=True)
    root_identity(state, initial=True)
    state.close()
    with sqlite3.connect(custody[0] / "identity.sqlite") as db:
        db.execute("UPDATE publications SET content='foreign' WHERE name='root-anchor/v1'")
    with pytest.raises(StateUnavailable, match="authentication"):
        open_store(custody)
