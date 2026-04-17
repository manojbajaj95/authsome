"""SQLite-backed key-value credential store with advisory file locking.

Spec §10: Uses SQLite as the KV backend for profiles/<name>/store.db.
Spec §25: Write operations guarded by profile-level advisory locking.
"""

from __future__ import annotations

import fcntl
import logging
import sqlite3
from pathlib import Path
from typing import IO

from authsome.errors import StoreUnavailableError
from authsome.store.base import CredentialStore

logger = logging.getLogger(__name__)

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class SQLiteStore(CredentialStore):
    """
    SQLite-backed key-value store for a single profile.

    Data is stored in profiles/<profile>/store.db as a simple kv table.
    Advisory file locking via profiles/<profile>/lock.
    """

    def __init__(self, profile_dir: Path) -> None:
        """
        Initialize the SQLite store for a profile directory.

        Args:
            profile_dir: Path to the profile directory (e.g., ~/.authsome/profiles/default/).
        """
        self._profile_dir = profile_dir
        self._db_path = profile_dir / "store.db"
        self._lock_path = profile_dir / "lock"
        self._conn: sqlite3.Connection | None = None
        self._lock_fd: IO[str] | None = None

        self._ensure_dir()
        self._connect()

    def _ensure_dir(self) -> None:
        """Create the profile directory if it doesn't exist."""
        self._profile_dir.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> None:
        """Open the SQLite connection and ensure the schema exists."""
        try:
            self._conn = sqlite3.connect(
                str(self._db_path),
                timeout=10.0,
                isolation_level="DEFERRED",
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_SCHEMA_SQL)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreUnavailableError(f"Failed to open store at {self._db_path}: {exc}") from exc

    def _acquire_lock(self) -> None:
        """Acquire an advisory write lock on the profile directory."""
        if self._lock_fd is not None:
            return  # Already locked
        try:
            self._lock_fd = open(self._lock_path, "w")  # noqa: SIM115
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        except OSError as exc:
            logger.warning("Advisory lock acquisition failed: %s", exc)

    def _release_lock(self) -> None:
        """Release the advisory write lock."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                self._lock_fd.close()
            except OSError:
                pass
            self._lock_fd = None

    def _ensure_connection(self) -> sqlite3.Connection:
        """Return the active connection, raising if closed."""
        if self._conn is None:
            raise StoreUnavailableError("Store connection is closed")
        return self._conn

    def get(self, key: str) -> str | None:
        """Retrieve a value by key."""
        conn = self._ensure_connection()
        cursor = conn.execute("SELECT value FROM kv WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def set(self, key: str, value: str) -> None:
        """Store a value by key with advisory locking."""
        conn = self._ensure_connection()
        self._acquire_lock()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()
        finally:
            self._release_lock()

    def delete(self, key: str) -> bool:
        """Delete a key from the store."""
        conn = self._ensure_connection()
        self._acquire_lock()
        try:
            cursor = conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            self._release_lock()

    def list_keys(self, prefix: str = "") -> list[str]:
        """List all keys matching a prefix."""
        conn = self._ensure_connection()
        if prefix:
            cursor = conn.execute(
                "SELECT key FROM kv WHERE key LIKE ? ORDER BY key",
                (prefix + "%",),
            )
        else:
            cursor = conn.execute("SELECT key FROM kv ORDER BY key")
        return [row[0] for row in cursor.fetchall()]

    def close(self) -> None:
        """Close the store connection and release the lock."""
        self._release_lock()
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
