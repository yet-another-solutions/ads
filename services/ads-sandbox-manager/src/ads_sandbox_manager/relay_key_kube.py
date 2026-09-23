"""Named immutable custody only; no discovery, copy, rotation or deletion."""

from __future__ import annotations

from kubernetes.client.exceptions import ApiException

from ads_sandbox_manager.kube import KubeClient
from ads_sandbox_manager.pair_kube import PairControlAdapter
from ads_sandbox_manager.pair_objects import PairBinding
from ads_sandbox_manager.relay_keys import (
    RelayKeys,
    custody_identity,
    custody_secret,
    validate_public_keys,
)


class RelayKeyAdapter:
    def __init__(self, kube: KubeClient) -> None:
        self.kube = kube

    @property
    def namespace(self) -> str:
        return self.kube.settings.namespace

    @property
    def golden_version(self) -> str:
        return self.kube.settings.golden_version

    async def _read(
        self, pair: PairBinding, public_keys: dict[str, str], uid: str | None
    ) -> tuple[str, RelayKeys] | None:
        validate_public_keys(public_keys)
        if uid is not None and (not isinstance(uid, str) or not uid.strip()):
            raise ValueError("invalid relay custody UID")
        desired = custody_identity(self.kube.settings, pair)
        try:
            observed = await self.kube._get(
                self.kube.core.read_namespaced_secret, desired["metadata"]["name"]
            )
        except Exception:
            # SDK exception bodies can include the Secret. Never propagate them.
            raise RuntimeError("relay custody read failed") from None
        if observed is None:
            return None
        result = PairControlAdapter._identity(observed, desired, uid)
        if (
            observed["metadata"].get("deletionTimestamp")
            or observed.get("type") != "Opaque"
            or observed.get("immutable") is not True
            or observed.get("stringData")
        ):
            raise RuntimeError("incompatible relay custody object")
        keys = RelayKeys.from_secret_data(observed.get("data"))
        if keys.public_keys() != public_keys:
            raise RuntimeError("relay custody public keys changed")
        return result, keys

    async def create(self, pair: PairBinding, public_keys: dict[str, str], keys: RelayKeys) -> str:
        """Only the original durable reservation may call this once."""
        validate_public_keys(public_keys)
        if keys.public_keys() != public_keys:
            raise ValueError("relay custody keys do not match reservation")
        try:
            await self.kube._call(
                self.kube.core.create_namespaced_secret,
                self.namespace,
                body=custody_secret(self.kube.settings, pair, keys),
            )
        except ApiException as exc:
            if exc.status != 409:
                raise RuntimeError("relay custody create failed") from None
        except Exception:
            raise RuntimeError("relay custody create failed") from None
        result = await self._read(pair, public_keys, None)
        if result is None:
            raise RuntimeError("relay custody create is not observable")
        return result[0]

    async def observe(
        self, pair: PairBinding, public_keys: dict[str, str], uid: str | None
    ) -> str | None:
        """Verified content observation, never recreation or dispatch settlement."""
        result = await self._read(pair, public_keys, uid)
        if result is None and uid is not None:
            raise RuntimeError("bound relay custody disappeared")
        return result[0] if result is not None else None

    async def load(self, pair: PairBinding, public_keys: dict[str, str], uid: str) -> RelayKeys:
        """Internal publisher input; caller must hold a current provisioning claim.

        No API returns this material. Never pass it to a guest, database, log,
        trace or exception. Per-relay publication remains a separate operation.
        """
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError("recorded relay custody UID required")
        result = await self._read(pair, public_keys, uid)
        if result is None:
            raise RuntimeError("bound relay custody disappeared")
        return result[1]
