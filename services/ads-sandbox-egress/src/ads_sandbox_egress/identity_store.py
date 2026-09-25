"""Encrypted sandbox-scoped identity storage, never a DNS answer cache.

The bootstrap owner must prove the exact mounted volume/custody and manager
replacement fence BEFORE opening this store. The local flock excludes writers
on this filesystem; it does not claim network ownership or fence another VM.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class StateUnavailable(Exception):
    pass


@dataclass(frozen=True, slots=True)
class StateIdentity:
    session_id: UUID
    sandbox_id: UUID
    project_id: UUID
    state_id: UUID
    pvc_uid: str
    custody_uid: str
    wrapping_fingerprint: str

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(v, UUID)
                for v in (self.session_id, self.sandbox_id, self.project_id, self.state_id)
            )
            or not self.pvc_uid
            or len(self.pvc_uid) > 128
            or not self.custody_uid
            or len(self.custody_uid) > 128
            or not re.fullmatch(r"[0-9a-f]{64}", self.wrapping_fingerprint)
        ):
            raise ValueError("invalid persistent custody identity")

    def encoded(self) -> bytes:
        return json.dumps(
            {key: str(value) for key, value in asdict(self).items()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


_SCHEMA = """
CREATE TABLE identity (singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                       format INTEGER NOT NULL CHECK(format=1),
                       binding BLOB NOT NULL, seal BLOB NOT NULL,
                       inventory BLOB NOT NULL);
CREATE TABLE keys (name TEXT PRIMARY KEY, kind TEXT NOT NULL,
                   public BLOB NOT NULL, sealed BLOB NOT NULL,
                   stage TEXT NOT NULL CHECK(stage IN
                   ('prepared','published','active','retiring','retired')));
CREATE TABLE publications (name TEXT PRIMARY KEY, content BLOB NOT NULL,
                           retain_until REAL NOT NULL);
CREATE TABLE dependencies (publication TEXT NOT NULL REFERENCES publications(name),
                           key_name TEXT NOT NULL REFERENCES keys(name),
                           PRIMARY KEY(publication,key_name));
"""


class IdentityStore:
    def __init__(
        self,
        directory: Path,
        identity: StateIdentity,
        wrapping_key: bytes,
        *,
        capacity: int,
        create: bool = False,
    ) -> None:
        if len(wrapping_key) != 32 or hashlib.sha256(wrapping_key).hexdigest() != (
            identity.wrapping_fingerprint
        ):
            raise StateUnavailable("wrapping custody mismatch")
        if type(capacity) is not int or capacity < 65536:
            raise ValueError("explicit state capacity required")
        info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise StateUnavailable("private owned state directory required")
        self.directory, self.identity, self.capacity = directory, identity, capacity
        self._cipher = AESGCM(wrapping_key)
        self._binding = identity.encoded()
        self._db: sqlite3.Connection | None = None
        self._lock = -1
        path = directory / "identity.sqlite"
        try:
            self._lock = os.open(
                directory / "owner.lock",
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            locked = os.fstat(self._lock)
            if (
                not stat.S_ISREG(locked.st_mode)
                or locked.st_uid != os.getuid()
                or (stat.S_IMODE(locked.st_mode) & 0o077 or locked.st_nlink != 1)
            ):
                raise StateUnavailable("unsafe owner lock")
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create:
                if set(item.name for item in directory.iterdir()) != {"owner.lock"}:
                    raise StateUnavailable(
                        "refusing initialization over retained or ambiguous state"
                    )
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            else:
                stored = path.lstat()
                if (
                    not stat.S_ISREG(stored.st_mode)
                    or stored.st_uid != os.getuid()
                    or (stored.st_nlink != 1 or stat.S_IMODE(stored.st_mode) & 0o077)
                ):
                    raise StateUnavailable("unsafe retained database")
            # Protect SQLite sidecars before opening; trusted parent is private.
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(path) + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    item = sidecar.lstat()
                    if (
                        not stat.S_ISREG(item.st_mode)
                        or item.st_uid != os.getuid()
                        or (item.st_nlink != 1 or stat.S_IMODE(item.st_mode) & 0o077)
                    ):
                        raise StateUnavailable("unsafe SQLite sidecar")
            self._db = sqlite3.connect(path.absolute().as_uri() + "?mode=rw", uri=True, timeout=0)
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA trusted_schema=OFF")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA journal_mode=DELETE")
            page_size = self._db.execute("PRAGMA page_size").fetchone()[0]
            self._db.execute(f"PRAGMA max_page_count={capacity // page_size}")
            if create:
                self._db.executescript(_SCHEMA)
                with self._db:
                    self._db.execute(
                        "INSERT INTO identity VALUES(1,1,?,?,?)",
                        (
                            self._binding,
                            self._seal(b"custody", b"ADS egress identity v1"),
                            self._seal(b"inventory", self._inventory()),
                        ),
                    )
                self._sync_directory()
            row = self._db.execute(
                "SELECT format,binding,seal FROM identity WHERE singleton=1"
            ).fetchone()
            if (
                row is None
                or row[:2] != (1, self._binding)
                or self._open(b"custody", row[2]) != b"ADS egress identity v1"
            ):
                raise StateUnavailable("retained identity mismatch")
            if self._db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise StateUnavailable("corrupt persistent state")
            self._verify_inventory()
        except BaseException:
            self.close()
            raise

    def _connection(self) -> sqlite3.Connection:
        if self._db is None:
            raise StateUnavailable("closed state")
        return self._db

    def _sync_directory(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _inventory(self) -> bytes:
        """Authenticate retained metadata as well as encrypted key material.

        This detects modified/deleted rows, stages, horizons and dependencies.
        It cannot detect replacement of the entire volume by an older, valid
        snapshot. Preventing that rollback belongs to manager custody/fencing.
        """
        digest = hashlib.sha256()
        total = 0
        for query in (
            "SELECT name,kind,public,sealed,stage FROM keys ORDER BY name",
            "SELECT name,content,retain_until FROM publications ORDER BY name",
            "SELECT publication,key_name FROM dependencies ORDER BY publication,key_name",
        ):
            digest.update(query.encode())
            for row in self._connection().execute(query):
                for value in row:
                    if isinstance(value, bytes):
                        encoded = b"B" + value
                    elif isinstance(value, str):
                        encoded = b"S" + value.encode()
                    elif isinstance(value, float):
                        encoded = b"F" + value.hex().encode()
                    else:
                        raise StateUnavailable("invalid persistent field type")
                    total += len(encoded) + 8
                    if total > self.capacity:
                        raise StateUnavailable("persistent inventory capacity")
                    digest.update(len(encoded).to_bytes(8, "big"))
                    digest.update(encoded)
        return digest.digest()

    def _verify_inventory(self) -> None:
        row = (
            self._connection()
            .execute("SELECT inventory FROM identity WHERE singleton=1")
            .fetchone()
        )
        if row is None or self._open(b"inventory", row[0]) != self._inventory():
            raise StateUnavailable("persistent inventory authentication failure")

    def _commit_inventory(self) -> None:
        # Called inside the SAME SQLite transaction as each publication/key edit.
        self._connection().execute(
            "UPDATE identity SET inventory=? WHERE singleton=1",
            (self._seal(b"inventory", self._inventory()),),
        )

    def _seal(self, label: bytes, value: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._cipher.encrypt(nonce, value, self._binding + b"\0" + label)

    def _open(self, label: bytes, value: bytes) -> bytes:
        try:
            return self._cipher.decrypt(value[:12], value[12:], self._binding + b"\0" + label)
        except (InvalidTag, ValueError):
            raise StateUnavailable("persistent authentication failure") from None

    @staticmethod
    def _name(name: str) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,512}", name):
            raise ValueError("invalid identity name")

    def _reserve(self, added: int) -> None:
        db = self._connection()
        used = db.execute(
            "SELECT (SELECT COALESCE(SUM(length(public)+length(sealed)+length(name)+128),0)"
            " FROM keys)+(SELECT COALESCE(SUM(length(content)+length(name)+128),0)"
            " FROM publications)"
        ).fetchone()[0]
        # Logical retained-data quota plus physical allocated database limit.
        physical = (
            db.execute("PRAGMA page_count").fetchone()[0]
            * db.execute("PRAGMA page_size").fetchone()[0]
        )
        if used + added > self.capacity or physical + added > self.capacity:
            raise StateUnavailable("persistent quota exhausted")

    def prepare_key(self, name: str, kind: str, public: bytes, private: bytes) -> None:
        self._name(name)
        if (
            kind not in ("root", "dnssec", "ech", "tls")
            or not public
            or not private
            or (len(public) > 65536 or len(private) > 65536)
        ):
            raise ValueError("invalid key generation")
        db = self._connection()
        self._verify_inventory()
        existing = db.execute(
            "SELECT kind,public,sealed FROM keys WHERE name=?", (name,)
        ).fetchone()
        label = self._key_label(name, kind, public)
        if existing is not None:
            if existing[:2] != (kind, public) or self._open(label, existing[2]) != private:
                raise StateUnavailable("key generation conflict")
            return
        if kind == "root" and db.execute("SELECT 1 FROM keys WHERE kind='root'").fetchone():
            raise StateUnavailable("root rotation is not supported")
        sealed = self._seal(label, private)
        with db:
            self._reserve(len(name) + len(public) + len(sealed) + 128)
            db.execute("INSERT INTO keys VALUES(?,?,?,?, 'prepared')", (name, kind, public, sealed))
            self._commit_inventory()
        self._sync_directory()

    def find_key(self, name: str) -> tuple[str, bytes, bytes, str] | None:
        """A genuine missing mapping differs from corrupt or retired state."""
        self._verify_inventory()
        row = (
            self._connection()
            .execute("SELECT kind,public,sealed,stage FROM keys WHERE name=?", (name,))
            .fetchone()
        )
        if row is None:
            return None
        if row[3] == "retired":
            raise StateUnavailable("required persistent key unavailable")
        return row[0], row[1], self._open(self._key_label(name, row[0], row[1]), row[2]), row[3]

    def key(self, name: str) -> tuple[str, bytes, bytes, str]:
        result = self.find_key(name)
        if result is None:
            raise StateUnavailable("required persistent key unavailable")
        return result

    @staticmethod
    def _key_label(name: str, kind: str, public: bytes) -> bytes:
        # The public configuration is inseparable from its encrypted private
        # material: disk corruption cannot silently substitute a different pair.
        return (kind + ":" + name).encode() + b"\0" + hashlib.sha256(public).digest()

    def advance(self, name: str, expected: str, target: str) -> None:
        stages = ("prepared", "published", "active", "retiring")
        if expected not in stages[:-1] or stages[stages.index(expected) + 1] != target:
            raise ValueError("invalid key stage transition")
        db = self._connection()
        self._verify_inventory()
        with db:
            if (
                db.execute(
                    "UPDATE keys SET stage=? WHERE name=? AND stage=?", (target, name, expected)
                ).rowcount
                != 1
            ):
                raise StateUnavailable("key stage changed")
            self._commit_inventory()

    def commit_publication(
        self, name: str, content: bytes, dependencies: tuple[str, ...], retain_until: float
    ) -> None:
        """Commit before wire publication and before exposing a new ECH config.

        Caller supplies the already-validated synthetic wire generation and a
        conservative absolute retention horizon covering every DNS/key/config
        dependency. This method neither resolves nor validates upstream DNS.
        """
        self._name(name)
        if (
            not content
            or len(content) > 1048576
            or not math.isfinite(retain_until)
            or (
                retain_until <= 0 or not dependencies or len(set(dependencies)) != len(dependencies)
            )
        ):
            raise ValueError("invalid publication")
        db = self._connection()
        self._verify_inventory()
        with db:
            existing = db.execute(
                "SELECT content,retain_until FROM publications WHERE name=?", (name,)
            ).fetchone()
            if existing is not None:
                original = tuple(
                    row[0]
                    for row in db.execute(
                        "SELECT key_name FROM dependencies WHERE publication=? ORDER BY key_name",
                        (name,),
                    )
                )
                if existing != (content, retain_until) or original != tuple(sorted(dependencies)):
                    raise StateUnavailable("publication conflict")
                return
            for dependency in dependencies:
                stage = self.key(dependency)[3]
                if stage not in ("published", "active", "retiring"):
                    raise StateUnavailable("unpublished dependency")
            self._reserve(len(name) + len(content) + 128 + 1024 * len(dependencies))
            db.execute("INSERT INTO publications VALUES(?,?,?)", (name, content, retain_until))
            db.executemany(
                "INSERT INTO dependencies VALUES(?,?)", ((name, d) for d in dependencies)
            )
            self._commit_inventory()
        self._sync_directory()

    def retire(self, name: str, *, now: float) -> None:
        if not math.isfinite(now) or now <= 0:
            raise ValueError("invalid retirement clock")
        db = self._connection()
        with db:
            key = self.key(name)
            if key[0] == "root" or key[3] != "retiring":
                raise StateUnavailable("key not eligible for retirement")
            if db.execute(
                "SELECT 1 FROM dependencies d JOIN publications p ON d.publication=p.name "
                "WHERE d.key_name=? AND p.retain_until>=? LIMIT 1",
                (name, now),
            ).fetchone():
                raise StateUnavailable("live publication dependency")
            # Retain the public mapping/tombstone; remove only private ciphertext.
            db.execute("UPDATE keys SET stage='retired',sealed=X'' WHERE name=?", (name,))
            self._commit_inventory()

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._lock >= 0:
            os.close(self._lock)
            self._lock = -1
