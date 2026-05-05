"""Local filesystem storage for config, providers, profiles, and vault data."""

from __future__ import annotations

import fcntl
import sqlite3
from pathlib import Path
from typing import IO

from loguru import logger

from authsome.auth.models.config import GlobalConfig
from authsome.auth.models.profile import ProfileMetadata
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import ProfileNotFoundError, ProviderNotFoundError, StoreUnavailableError
from authsome.utils import utc_now


class SQLiteVaultStorage:
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
            self._conn.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);")
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


class LocalAppStore:
    """Local filesystem storage implementation."""

    def __init__(self, home_dir: Path) -> None:
        self._home = home_dir
        self._config_path = self._home / "config.json"
        self._providers_dir = self._home / "providers"
        self._profiles_dir = self._home / "profiles"
        self._vault_stores: dict[str, SQLiteVaultStorage] = {}

    @property
    def home(self) -> Path:
        return self._home

    def ensure_initialized(self) -> None:
        if (self._home / "version").exists() and (self._profiles_dir / "default").exists():
            return

        self._home.mkdir(parents=True, exist_ok=True)
        self._providers_dir.mkdir(parents=True, exist_ok=True)
        (self._profiles_dir / "default").mkdir(parents=True, exist_ok=True)

        version_file = self._home / "version"
        if not version_file.exists():
            version_file.write_text("2\n", encoding="utf-8")

        if not self._config_path.exists():
            self.save_config(GlobalConfig())

        try:
            self.get_profile("default")
        except ProfileNotFoundError:
            now = utc_now()
            self.save_profile(
                ProfileMetadata(
                    name="default",
                    created_at=now,
                    updated_at=now,
                    description="Default local profile",
                )
            )

    def is_healthy(self) -> bool:
        return self._home.exists() and self._config_path.exists()

    # ── Config ────────────────────────────────────────────────────────────

    def get_config(self) -> GlobalConfig:
        if not self._config_path.exists():
            return GlobalConfig()
        try:
            return GlobalConfig.model_validate_json(self._config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse config.json, using defaults: {}", exc)
            return GlobalConfig()

    def save_config(self, config: GlobalConfig) -> None:
        self._home.mkdir(parents=True, exist_ok=True)
        self._config_path.write_text(config.model_dump_json(indent=2), encoding="utf-8")

    # ── Profiles ──────────────────────────────────────────────────────────

    def get_profile(self, name: str) -> ProfileMetadata:
        path = self._profiles_dir / name / "metadata.json"
        if not path.exists():
            raise ProfileNotFoundError(name)
        return ProfileMetadata.model_validate_json(path.read_text(encoding="utf-8"))

    def save_profile(self, metadata: ProfileMetadata) -> None:
        dir_path = self._profiles_dir / metadata.name
        dir_path.mkdir(parents=True, exist_ok=True)
        path = dir_path / "metadata.json"
        path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")

    def list_profiles(self) -> list[ProfileMetadata]:
        if not self._profiles_dir.exists():
            return []
        profiles = []
        for d in self._profiles_dir.iterdir():
            if d.is_dir() and (d / "metadata.json").exists():
                try:
                    profiles.append(self.get_profile(d.name))
                except Exception as e:
                    logger.warning("Failed to load profile {}: {}", d.name, e)
        return sorted(profiles, key=lambda p: p.name)

    def delete_profile(self, name: str) -> None:
        if name == "default":
            raise ValueError("Cannot delete default profile")

        # Close vault connection if open
        if name in self._vault_stores:
            self._vault_stores[name].close()
            del self._vault_stores[name]

        dir_path = self._profiles_dir / name
        if not dir_path.exists():
            raise ProfileNotFoundError(name)

        import shutil

        shutil.rmtree(dir_path)

    # ── Providers ─────────────────────────────────────────────────────────

    def get_provider(self, name: str) -> ProviderDefinition:
        path = self._providers_dir / f"{name}.json"
        if not path.exists():
            raise ProviderNotFoundError(name)
        return ProviderDefinition.model_validate_json(path.read_text(encoding="utf-8"))

    def save_provider(self, definition: ProviderDefinition) -> None:
        self._providers_dir.mkdir(parents=True, exist_ok=True)
        path = self._providers_dir / f"{definition.name}.json"
        path.write_text(definition.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")

    def list_providers(self) -> list[ProviderDefinition]:
        if not self._providers_dir.exists():
            return []
        providers = []
        for path in self._providers_dir.glob("*.json"):
            try:
                providers.append(ProviderDefinition.model_validate_json(path.read_text(encoding="utf-8")))
            except Exception as e:
                logger.warning("Failed to load custom provider from {}: {}", path, e)
        return sorted(providers, key=lambda p: p.name)

    def delete_provider(self, name: str) -> None:
        path = self._providers_dir / f"{name}.json"
        if not path.exists():
            raise ProviderNotFoundError(name)
        path.unlink()

    # ── Vault ─────────────────────────────────────────────────────────────

    def get_vault_storage(self, profile: str) -> SQLiteVaultStorage:
        if profile not in self._vault_stores:
            profile_dir = self._profiles_dir / profile
            if not profile_dir.exists():
                raise ProfileNotFoundError(profile)
            self._vault_stores[profile] = SQLiteVaultStorage(profile_dir)
        return self._vault_stores[profile]

    def close(self) -> None:
        for store in self._vault_stores.values():
            store.close()
        self._vault_stores.clear()
