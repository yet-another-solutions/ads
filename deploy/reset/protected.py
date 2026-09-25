"""Protected external reset records. Never emit plaintext or credential hashes."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = b"ads-protected-reset-v1"
MAX_BYTES = 64 * 1024 * 1024


class PreservationError(RuntimeError):
    pass


def _json(raw: bytes) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PreservationError("duplicate protected record field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=unique)


class ProtectedStore:
    """External 0700 directory, 0600 files, authenticated encryption, fsync.

    The directory and key are an operator-provisioned recovery destination.
    No key is generated implicitly. The caller must retain this destination
    across all resets; deleting it is deliberately not an exposed operation.
    """

    def __init__(self, directory: Path, *, source_root: Path) -> None:
        root = directory.absolute()
        if root != root.resolve() or root.is_relative_to(source_root.resolve()):
            raise PreservationError("protected destination must be external and non-symlinked")
        observed = root.stat()
        if (
            not stat.S_ISDIR(observed.st_mode)
            or observed.st_uid != os.geteuid()
            or stat.S_IMODE(observed.st_mode) != 0o700
        ):
            raise PreservationError("protected destination requires private owned directory")
        self.path = root
        self.directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        actual = os.fstat(self.directory)
        if (actual.st_dev, actual.st_ino) != (observed.st_dev, observed.st_ino):
            os.close(self.directory)
            raise PreservationError("protected directory changed")
        try:
            key = self._read("key", limit=32)
            if len(key) != 32:
                raise PreservationError("external 256-bit recovery key required")
            self.cipher = AESGCM(key)
        except BaseException:
            os.close(self.directory)
            raise

    def close(self) -> None:
        os.close(self.directory)

    @staticmethod
    def _name(name: str) -> str:
        if name not in (
            "key",
            "models",
            "checkpoint",
            "associations",
            "owner-auth",
            "configuration",
            "lock",
        ):
            raise PreservationError("unsupported protected record")
        return name

    def _read(self, name: str, *, limit: int = MAX_BYTES) -> bytes:
        fd = os.open(self._name(name), os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.directory)
        try:
            meta = os.fstat(fd)
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_nlink != 1
                or not 0 < meta.st_size <= limit
            ):
                raise PreservationError("protected file ownership, mode or size invalid")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(limit + 1)
            if not 0 < len(raw) <= limit:
                raise PreservationError("protected record exceeds size bound")
            return raw
        finally:
            os.close(fd)

    def read(self, name: str) -> Any:
        if name in ("key", "lock"):
            raise PreservationError("raw key export is not supported")
        try:
            raw = self._read(name)
            return _json(self.cipher.decrypt(raw[:12], raw[12:], DOMAIN + name.encode()))
        except FileNotFoundError:
            raise
        except Exception:
            raise PreservationError("protected record verification failed") from None

    def write(self, name: str, value: Any) -> None:
        self._name(name)
        if name in ("key", "lock"):
            raise PreservationError("recovery key replacement is not supported")
        try:
            raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            if len(raw) > MAX_BYTES - 64:
                raise PreservationError("protected record exceeds size bound")
            nonce = os.urandom(12)
            encrypted = nonce + self.cipher.encrypt(nonce, raw, DOMAIN + name.encode())
            temporary = "." + name + "-" + os.urandom(12).hex()
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=self.directory,
            )
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(encrypted)
                    stream.flush()
                    os.fsync(fd)
                os.rename(temporary, name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
                os.fsync(self.directory)
            finally:
                os.close(fd)
                try:
                    os.unlink(temporary, dir_fd=self.directory)
                except FileNotFoundError:
                    pass
            if self.read(name) != value:
                raise PreservationError("protected roundtrip verification failed")
        except Exception:
            raise PreservationError("protected record write failed") from None

    @contextmanager
    def lock(self):
        fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
        try:
            meta = os.fstat(fd)
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.geteuid()
                or stat.S_IMODE(meta.st_mode) != 0o600
                or meta.st_nlink != 1
            ):
                raise PreservationError("unsafe reset lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PreservationError("another reset owns the external checkpoint") from None
            yield
        finally:
            os.close(fd)
