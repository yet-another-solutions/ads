"""Paired transport keys. Never serialize private material into SQL or logs."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ads_sandbox_manager.config import Settings
from ads_sandbox_manager.objects import Object
from ads_sandbox_manager.pair_objects import PairBinding, metadata

RELAY_SIDES = ("guest", "egress")


def key_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("invalid relay key encoding")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid relay key encoding") from None
    if len(raw) != 32 or not any(raw) or base64.b64encode(raw).decode() != value:
        raise ValueError("invalid relay key encoding")
    return raw


def validate_public_keys(value: object) -> None:
    if not isinstance(value, dict) or set(value) != set(RELAY_SIDES):
        raise ValueError("invalid paired relay public keys")
    for key in value.values():
        key_bytes(key)
    if value["guest"] == value["egress"]:
        raise ValueError("relay keys must be distinct")


@dataclass(frozen=True, slots=True)
class RelayKeys:
    guest: bytes = field(repr=False)
    egress: bytes = field(repr=False)

    def __post_init__(self) -> None:
        for raw in (self.guest, self.egress):
            # WireGuard private scalar canonicalization, not merely X25519's
            # implicit clamping of arbitrary input. Reject zero/noncanonical keys.
            if (
                not isinstance(raw, bytes)
                or len(raw) != 32
                or raw[0] & 7
                or raw[31] & 128
                or not raw[31] & 64
            ):
                raise ValueError("invalid relay private key")
        validate_public_keys(self.public_keys())

    @classmethod
    def generate(cls) -> RelayKeys:
        return cls(
            X25519PrivateKey.generate().private_bytes_raw(),
            X25519PrivateKey.generate().private_bytes_raw(),
        )

    def public_keys(self) -> dict[str, str]:
        return {
            side: base64.b64encode(
                X25519PrivateKey.from_private_bytes(getattr(self, side))
                .public_key()
                .public_bytes_raw()
            ).decode()
            for side in RELAY_SIDES
        }

    def secret_data(self) -> dict[str, str]:
        # Kubernetes data is base64 of file bytes; each file contains the
        # WireGuard base64 scalar plus newline, not the raw scalar.
        return {
            side + ".key": base64.b64encode(base64.b64encode(getattr(self, side)) + b"\n").decode()
            for side in RELAY_SIDES
        }

    @classmethod
    def from_secret_data(cls, data: object) -> RelayKeys:
        if not isinstance(data, dict) or set(data) != {side + ".key" for side in RELAY_SIDES}:
            raise ValueError("invalid relay custody data")
        raw = []
        try:
            for side in RELAY_SIDES:
                encoded = data[side + ".key"]
                text = base64.b64decode(encoded, validate=True)
                if base64.b64encode(text).decode() != encoded or not text.endswith(b"\n"):
                    raise ValueError
                raw.append(key_bytes(text[:-1].decode("ascii")))
            return cls(*raw)
        except (ValueError, TypeError, UnicodeError, binascii.Error):
            raise ValueError("invalid relay custody data") from None


def custody_identity(settings: Settings, pair: PairBinding) -> Object:
    meta = metadata(settings, pair, "guest-relay")
    meta["name"] = f"ads-relay-keys-{pair.sandbox_id}.{pair.generation}"
    meta["labels"]["ads.io/relay-input"] = "custody"
    return {"apiVersion": "v1", "kind": "Secret", "metadata": meta}


def custody_secret(settings: Settings, pair: PairBinding, keys: RelayKeys) -> Object:
    return {
        **custody_identity(settings, pair),
        "type": "Opaque",
        "immutable": True,
        "data": keys.secret_data(),
    }
