"""Manager ↔ ipc ping body on ads.sandbox.ping.req and ads.sandbox.ping.res."""

from __future__ import annotations

import uuid

import msgspec


class SandboxPing(msgspec.Struct, frozen=True, forbid_unknown_fields=True):
    ping_id: uuid.UUID
    sandbox_id: uuid.UUID


def decode_ping(raw: bytes) -> SandboxPing:
    return msgspec.json.decode(raw, type=SandboxPing)


def encode_ping(message: SandboxPing) -> bytes:
    return msgspec.json.encode(message)
