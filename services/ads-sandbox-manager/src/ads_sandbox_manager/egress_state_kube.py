"""Exact persistent custody/storage publication; no mount, clone or deletion."""

from __future__ import annotations

import base64
import binascii
from copy import deepcopy

from kubernetes.client.exceptions import ApiException
from kubernetes.utils.quantity import parse_quantity

from ads_sandbox_manager.egress_state_objects import identity as identity
from ads_sandbox_manager.egress_state_store import EgressState, WrappingKey, validate
from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_kube import PairControlAdapter


def key_secret(state: EgressState, key: WrappingKey) -> Object:
    if key.fingerprint != state.key_fingerprint:
        raise ValueError("wrapping key does not match committed reservation")
    return {
        **identity(state, "key"),
        "type": "Opaque",
        "immutable": True,
        # SecretKeyRef delivers UTF-8 environment text without a filesystem
        # volume, unlike arbitrary raw bytes. Kubernetes data adds its own base64.
        "data": {"wrapping.b64": base64.b64encode(base64.b64encode(key.value)).decode("ascii")},
    }


def state_volume(state: EgressState) -> Object:
    if state.key_uid is None or state.key_dispatch != "settled":
        raise ValueError("bound settled wrapping custody required")
    desired = identity(state, "volume")
    desired["metadata"]["labels"]["ads.io/wrapping-custody-uid"] = state.key_uid
    desired["spec"] = {
        "storageClassName": "sandbox-block",
        "volumeMode": "Block",
        "accessModes": ["ReadWriteOnce"],
        "resources": {"requests": {"storage": str(state.storage_bytes)}},
    }
    return desired


def decode_key(data: object, fingerprint: str) -> WrappingKey:
    try:
        if not isinstance(data, dict) or set(data) != {"wrapping.b64"}:
            raise ValueError
        encoded = data["wrapping.b64"]
        text = base64.b64decode(encoded, validate=True)
        if base64.b64encode(text).decode("ascii") != encoded:
            raise ValueError
        raw = base64.b64decode(text, validate=True)
        if base64.b64encode(raw) != text:
            raise ValueError
        key = WrappingKey(raw)
        if key.fingerprint != fingerprint:
            raise ValueError
        return key
    except (TypeError, ValueError, binascii.Error):
        # Never echo private material or SDK bodies, including malformed data.
        raise ValueError("invalid persistent wrapping custody") from None


def volume_matches(observed: Object, desired: Object) -> bool:
    actual = deepcopy(observed.get("spec", {}))
    assigned = actual.pop("volumeName", None)
    if assigned is not None and (not isinstance(assigned, str) or not assigned.strip()):
        return False
    try:
        resources = actual["resources"]
        if set(resources) != {"requests"} or set(resources["requests"]) != {"storage"}:
            return False
        size = resources["requests"]["storage"]
        expected = desired["spec"]["resources"]["requests"]["storage"]
        if parse_quantity(size) != parse_quantity(expected):
            return False
        resources["requests"]["storage"] = expected
    except (KeyError, TypeError, ValueError, ArithmeticError):
        return False
    return bool(actual == desired["spec"])


class EgressStateAdapter:
    """Original reservation creates once; restart is content-verified read only.

    No API exception body escapes this adapter: Secret errors may contain keys.
    API absence never authorizes recreation of a recorded resource.
    """

    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube

    def _configuration(self, state: EgressState) -> None:
        validate(state)
        if state.namespace != self.kube.settings.namespace:
            raise RuntimeError("persistent state namespace changed")

    async def _read(self, state: EgressState, role: str) -> Object | None:
        self._configuration(state)
        desired = identity(state, role) if role == "key" else state_volume(state)
        method = (
            self.kube.core.read_namespaced_secret
            if role == "key"
            else self.kube.core.read_namespaced_persistent_volume_claim
        )
        try:
            observed = await self.kube._get(method, desired["metadata"]["name"])
        except Exception:
            raise RuntimeError("persistent state resource read failed") from None
        uid = state.key_uid if role == "key" else state.volume_uid
        if observed is None:
            if uid is not None:
                raise RuntimeError("bound persistent state resource disappeared")
            return None
        PairControlAdapter._identity(observed, desired, uid)
        if observed["metadata"].get("deletionTimestamp"):
            raise RuntimeError("persistent state resource is deleting")
        if role == "key":
            if (
                observed.get("type") != "Opaque"
                or observed.get("immutable") is not True
                or observed.get("stringData")
            ):
                raise RuntimeError("incompatible persistent wrapping custody")
            decode_key(observed.get("data"), state.key_fingerprint)
        elif observed.get("status", {}).get("phase") == "Lost" or not volume_matches(
            observed, desired
        ):
            raise RuntimeError("incompatible persistent state volume")
        return observed

    async def observe_key(self, state: EgressState) -> str | None:
        observed = await self._read(state, "key")
        return observed["metadata"]["uid"] if observed is not None else None

    async def load_key(self, state: EgressState) -> WrappingKey:
        """Internal future bootstrap input; not an HTTP endpoint or guest input."""
        if state.key_uid is None:
            raise ValueError("recorded wrapping custody UID required")
        observed = await self._read(state, "key")
        assert observed is not None  # Bound absence raises.
        return decode_key(observed.get("data"), state.key_fingerprint)

    async def observe_volume(self, state: EgressState) -> str | None:
        if state.key_uid is None:
            raise ValueError("recorded wrapping custody UID required")
        await self.load_key(state)
        observed = await self._read(state, "volume")
        await self.load_key(state)
        return observed["metadata"]["uid"] if observed is not None else None

    async def _create(self, state: EgressState, role: str, body: Object) -> None:
        self._configuration(state)
        if (
            getattr(state, f"{role}_dispatch") != "inflight"
            or getattr(state, f"{role}_uid") is not None
        ):
            raise RuntimeError("original unbound persistent state dispatch required")
        method = (
            self.kube.core.create_namespaced_secret
            if role == "key"
            else self.kube.core.create_namespaced_persistent_volume_claim
        )
        try:
            await self.kube._call(method, state.namespace, body=body)
        except ApiException as exc:
            if exc.status != 409:
                raise RuntimeError("persistent state resource create failed") from None
        except Exception:
            raise RuntimeError("persistent state resource create failed") from None

    async def create_key(self, state: EgressState, key: WrappingKey) -> str:
        await self._create(state, "key", key_secret(state, key))
        uid = await self.observe_key(state)
        if uid is None:
            raise RuntimeError("persistent wrapping custody create not observable")
        return uid

    async def create_volume(self, state: EgressState) -> str:
        await self.load_key(state)
        await self._create(state, "volume", state_volume(state))
        uid = await self.observe_volume(state)
        if uid is None:
            raise RuntimeError("persistent state volume create not observable")
        return uid
