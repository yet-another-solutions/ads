# ruff: noqa: F811
from __future__ import annotations

import base64
from copy import deepcopy
from unittest.mock import patch
from uuid import uuid4

import pytest
from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.relay_key_kube import RelayKeyAdapter
from ads_sandbox_manager.relay_keys import (
    RelayKeys,
    custody_identity,
    custody_secret,
    key_bytes,
    validate_public_keys,
)
from test_kube_release import api  # noqa: F401
from test_pair_objects import pair  # noqa: F401
from test_session_objects import object_settings  # noqa: F401


def test_keys_are_distinct_canonical_and_roundtrip_without_leaking_repr():
    keys = RelayKeys.generate()
    assert keys.guest != keys.egress
    assert keys.public_keys()["guest"] != keys.public_keys()["egress"]
    assert RelayKeys.from_secret_data(keys.secret_data()) == keys
    assert repr(keys) == "RelayKeys()"
    for raw in (keys.guest, keys.egress):
        assert len(raw) == 32 and raw[0] & 7 == 0
        assert raw[31] & 128 == 0 and raw[31] & 64
    with patch.object(RelayKeys, "generate", side_effect=AssertionError("must not generate")):
        assert RelayKeys.from_secret_data(keys.secret_data()) == keys


@pytest.mark.parametrize("value", [None, False, 1, "", "!", "AAAA", "A" * 44, "A" * 43 + "="])
def test_public_key_encoding_rejects_invalid_values(value):
    with pytest.raises(ValueError, match="encoding"):
        key_bytes(value)


@pytest.mark.parametrize("value", [None, {}, [], {"guest": "x"}, {"guest": "x", "egress": "x"}])
def test_public_pair_shape_is_exact(value):
    with pytest.raises(ValueError):
        validate_public_keys(value)


def test_same_public_key_is_refused():
    public = RelayKeys.generate().public_keys()["guest"]
    with pytest.raises(ValueError, match="distinct"):
        validate_public_keys({"guest": public, "egress": public})


@pytest.mark.parametrize("raw", [b"", bytes(32), bytes([255]) * 32, "not-bytes", bytes(31)])
def test_private_scalars_are_validated(raw):
    with pytest.raises(ValueError, match="private key"):
        RelayKeys(raw, RelayKeys.generate().egress)


def test_equal_private_keys_are_refused():
    raw = RelayKeys.generate().guest
    with pytest.raises(ValueError, match="distinct"):
        RelayKeys(raw, raw)


@pytest.mark.parametrize("mutation", ["missing", "extra", "bad-base64", "no-newline", "bad-scalar"])
def test_corrupt_secret_cannot_be_repaired_or_regenerated(mutation):
    data = RelayKeys.generate().secret_data()
    if mutation == "missing":
        data.pop("guest.key")
    elif mutation == "extra":
        data["foreign"] = "value"
    elif mutation == "bad-base64":
        data["guest.key"] = "!"
    elif mutation == "no-newline":
        data["guest.key"] = base64.b64encode(base64.b64decode(data["guest.key"])[:-1]).decode()
    else:
        data["guest.key"] = base64.b64encode(base64.b64encode(bytes(32)) + b"\n").decode()
    with pytest.raises(ValueError, match="custody data"):
        RelayKeys.from_secret_data(data)


def test_custody_is_one_generation_scoped_immutable_unmounted_secret(object_settings, pair):
    body = custody_secret(object_settings, pair, RelayKeys.generate())
    assert body["type"] == "Opaque" and body["immutable"] is True
    assert set(body["data"]) == {"guest.key", "egress.key"}
    assert body["metadata"]["namespace"] == object_settings.namespace
    assert body["metadata"]["name"] == f"ads-relay-keys-{pair.sandbox_id}.{pair.generation}"
    assert not body["metadata"].get("ownerReferences")
    assert all(len(label) <= 63 for label in body["metadata"]["name"].split("."))


@pytest.fixture
def custody(api, pair):
    adapter = RelayKeyAdapter(api)
    keys = RelayKeys.generate()
    body = custody_secret(api.settings, pair, keys)
    body["metadata"].update(uid=str(uuid4()), resourceVersion="1")
    api.core.read_namespaced_secret.return_value = body
    api.core.create_namespaced_secret.return_value = body
    return adapter, pair, keys, body


@pytest.mark.anyio
async def test_adapter_creates_atomically_and_restart_loads_exact_original_keys(custody):
    adapter, pair, keys, body = custody
    public = keys.public_keys()
    uid = await adapter.create(pair, public, keys)
    create = adapter.kube.core.create_namespaced_secret
    assert create.call_count == 1
    assert create.call_args.kwargs["body"] == custody_secret(adapter.kube.settings, pair, keys)
    assert create.call_args.kwargs["_request_timeout"] == adapter.kube.settings.control_seconds
    assert create.call_args.args == (adapter.namespace,)
    assert uid == body["metadata"]["uid"]
    adapter = RelayKeyAdapter(adapter.kube)
    assert await adapter.observe(pair, public, uid) == uid
    assert await adapter.load(pair, public, uid) == keys
    assert create.call_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mutation",
    [
        "uid",
        "name",
        "namespace",
        "labels",
        "owner",
        "version",
        "deleting",
        "type",
        "mutable",
        "data",
        "foreign-keys",
        "stringData",
    ],
)
async def test_adapter_rejects_untrusted_or_replaced_custody(custody, mutation):
    adapter, pair, keys, body = custody
    uid = body["metadata"]["uid"]
    if mutation in ("uid", "name", "namespace"):
        body["metadata"][mutation] = "foreign"
    elif mutation == "labels":
        body["metadata"]["labels"] = {}
    elif mutation == "owner":
        body["metadata"]["ownerReferences"] = [{"uid": "controller"}]
    elif mutation == "version":
        body["metadata"]["resourceVersion"] = " "
    elif mutation == "deleting":
        body["metadata"]["deletionTimestamp"] = "now"
    elif mutation == "type":
        body["type"] = "kubernetes.io/tls"
    elif mutation == "mutable":
        body["immutable"] = False
    elif mutation == "data":
        body["data"] = {}
    elif mutation == "foreign-keys":
        body["data"] = RelayKeys.generate().secret_data()
    else:
        body["stringData"] = {"unexpected": "value"}
    with pytest.raises((ValueError, RuntimeError)):
        await adapter.load(pair, keys.public_keys(), uid)
    adapter.kube.core.create_namespaced_secret.assert_not_called()


@pytest.mark.anyio
async def test_absent_or_lost_custody_never_recreates(custody):
    adapter, pair, keys, body = custody
    adapter.kube.core.read_namespaced_secret.side_effect = ApiException(status=404)
    assert await adapter.observe(pair, keys.public_keys(), None) is None
    with pytest.raises(RuntimeError, match="disappeared"):
        await adapter.load(pair, keys.public_keys(), body["metadata"]["uid"])
    with pytest.raises(RuntimeError, match="disappeared"):
        await adapter.observe(pair, keys.public_keys(), body["metadata"]["uid"])
    with pytest.raises(ValueError, match="UID"):
        await adapter.load(pair, keys.public_keys(), "")
    adapter.kube.core.create_namespaced_secret.assert_not_called()


@pytest.mark.anyio
async def test_create_conflict_requires_the_original_pair_of_public_keys(custody):
    adapter, pair, keys, body = custody
    adapter.kube.core.create_namespaced_secret.side_effect = ApiException(status=409)
    assert await adapter.create(pair, keys.public_keys(), keys) == body["metadata"]["uid"]
    foreign = RelayKeys.generate()
    with pytest.raises(ValueError, match="reservation"):
        await adapter.create(pair, keys.public_keys(), foreign)
    with pytest.raises(RuntimeError, match="public keys"):
        await adapter.create(pair, foreign.public_keys(), foreign)


@pytest.mark.anyio
@pytest.mark.parametrize("operation", ["read", "create", "cleanup"])
async def test_sdk_error_bodies_never_escape(custody, operation):
    adapter, pair, keys, body = custody
    error = ApiException(status=403, reason="SENSITIVE-BODY")
    adapter.kube.core.read_namespaced_secret.side_effect = error
    adapter.kube.core.create_namespaced_secret.side_effect = error
    with pytest.raises(RuntimeError) as raised:
        if operation == "create":
            await adapter.create(pair, keys.public_keys(), keys)
        elif operation == "read":
            await adapter.load(pair, keys.public_keys(), body["metadata"]["uid"])
        else:
            await PairControlAdapter(adapter.kube).observe_relay_custody(pair, None)
    assert "SENSITIVE" not in str(raised.value)
    assert raised.value.__suppress_context__


@pytest.mark.anyio
async def test_cleanup_captures_drifted_deleting_secret_but_never_returns_keys(custody):
    adapter, pair, keys, body = custody
    expected_uid = body["metadata"]["uid"]
    body["metadata"]["deletionTimestamp"] = "now"
    body["data"] = {"corrupt": "still-an-obligation"}
    body["immutable"] = False
    cleanup = PairControlAdapter(adapter.kube)
    assert await cleanup.observe_relay_custody(pair, expected_uid) == expected_uid
    read = adapter.kube.core.read_namespaced_secret
    assert read.call_args.args == (
        custody_identity(adapter.kube.settings, pair)["metadata"]["name"],
        adapter.namespace,
    )
    original = deepcopy(body)
    body["metadata"]["uid"] = "replacement"
    with pytest.raises(RuntimeError, match="replaced"):
        await cleanup.observe_relay_custody(pair, expected_uid)
    body.update(original)
    adapter.kube.core.create_namespaced_secret.assert_not_called()
