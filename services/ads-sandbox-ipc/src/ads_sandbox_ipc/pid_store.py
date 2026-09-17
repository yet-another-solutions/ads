from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from uuid import UUID

from ads_sandbox_ipc.config import Settings


@dataclass(frozen=True, slots=True)
class GuestPid:
    pod_uid: str
    pid: int

    def __post_init__(self) -> None:
        if not self.pod_uid or type(self.pid) is not int or self.pid <= 1:
            raise ValueError("invalid guest pid")


class PidStore:
    """Atomic, fsynced PVC records. Never persist input, output, identity, or JWTs."""

    def __init__(self, settings: Settings) -> None:
        self._directory = settings.pid_directory
        self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _sync_directory(self) -> None:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def save(self, execution_id: UUID, entry: GuestPid) -> None:
        target = self._directory / f"{execution_id}.json"
        temporary = target.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(asdict(entry), stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        self._sync_directory()

    def entries(self) -> list[tuple[UUID, GuestPid]]:
        result = []
        for path in sorted(self._directory.glob("*.json")):
            # Corruption fails startup closed; it must never silently discard a live pid.
            payload = json.loads(path.read_text(encoding="utf-8"))
            result.append((UUID(path.stem), GuestPid(**payload)))
        return result

    def remove(self, execution_id: UUID) -> None:
        (self._directory / f"{execution_id}.json").unlink(missing_ok=True)
        self._sync_directory()

    def clear(self) -> None:
        for path in self._directory.iterdir():
            if path.suffix in {".json", ".tmp"}:
                path.unlink()
        self._sync_directory()
