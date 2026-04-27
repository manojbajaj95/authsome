"""SQLite-backed key-value storage for the Vault.

Internal to vault/. Not imported from outside the vault package.
Uses WAL mode and fcntl advisory locking for concurrent safety.
"""

from __future__ import annotations

import fcntl
import sqlite3
from pathlib import Path
from typing import IO

from loguru import logger

from authsome.errors import StoreUnavailableError

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class SQLiteStorage:
    """SQLite KV store for a single profile directory."""

    def __init__(self, profile_dir: Path) -> None:
        self._profile_dir = profile_dir
        self._db_path = profile_dir / "store.db"
        self._lock_path = profile_dir / "lock"
        self._conn: sqlite3.Connection | None = None
        self._lock_fd: IO[str] | None = None
        self._profile_dir.mkdir(parents=True, exist_ok=True)
        self._connect()

    def _connect(self) -> None:
        try:
            self._conn = sqlite3.connect(
                str(self._db_path),
                timeout=10.0,
                isolation_level="DEFERRED",
                check_same_thread=False,
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_SCHEMA_SQL)
            self._conn.commit()
        except sqlite3.Error as exc:
            raise StoreUnavailableError(f"Failed to open store at {self._db_path}: {exc}") from exc

    def _acquire_lock(self) -> None:
        if self._lock_fd is not None:
            return
        try:
            self._lock_fd = open(self._lock_path, "w")  # noqa: SIM115
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        except OSError as exc:
            logger.warning("Advisory lock acquisition failed: {}", exc)

    def _release_lock(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                self._lock_fd.close()
            except OSError:
                pass
            self._lock_fd = None

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StoreUnavailableError("Store connection is closed")
        return self._conn

    def get(self, key: str) -> str | None:
        conn = self._ensure_connection()
        cursor = conn.execute("SELECT value FROM kv WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row[0] if row else None

    def put(self, key: str, value: str) -> None:
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
        conn = self._ensure_connection()
        self._acquire_lock()
        try:
            cursor = conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            self._release_lock()

    def list_keys(self, prefix: str = "") -> list[str]:
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
        self._release_lock()
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
