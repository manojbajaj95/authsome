"""Vault — the secure credential store.

The Vault is a generic encrypted key-value store. It owns:
- The master key (via a pluggable crypto backend)
- The SQLite storage backend
- Encryption and decryption of all stored values

The Vault knows nothing about credential types, token lifecycle, or OAuth.
All key schema decisions belong to the caller (AuthLayer).
"""

from __future__ import annotations

import builtins
import logging
from pathlib import Path

from authsome.vault.crypto import VaultCrypto, create_crypto
from authsome.vault.storage import SQLiteStorage

logger = logging.getLogger(__name__)

_DEFAULT_PROFILE = "default"


class Vault:
    """
    Encrypted key-value store backed by SQLite.

    All values are encrypted at rest using AES-256-GCM. The master key is
    managed by the configured VaultCrypto backend (local file or OS keyring).

    The Vault is key-agnostic. Key schema is owned by AuthLayer.
    """

    def __init__(
        self,
        home: Path,
        crypto_mode: str = "local_key",
        _crypto: VaultCrypto | None = None,
    ) -> None:
        self._home = home
        self._crypto_mode = crypto_mode
        self._crypto: VaultCrypto | None = _crypto
        self._stores: dict[str, SQLiteStorage] = {}

    # ── Lazy crypto init ──────────────────────────────────────────────────

    @property
    def crypto(self) -> VaultCrypto:
        if self._crypto is None:
            self._crypto = create_crypto(self._home, self._crypto_mode)
        return self._crypto

    # ── Core KV interface ─────────────────────────────────────────────────

    def get(self, key: str, *, profile: str = _DEFAULT_PROFILE) -> str | None:
        """Retrieve and decrypt a value. Returns None if key not found."""
        raw = self._storage(profile).get(key)
        if raw is None:
            return None
        return self.crypto.decrypt(raw)

    def put(self, key: str, value: str, *, profile: str = _DEFAULT_PROFILE) -> None:
        """Encrypt and store a value."""
        encrypted = self.crypto.encrypt(value)
        self._storage(profile).put(key, encrypted)

    def delete(self, key: str, *, profile: str = _DEFAULT_PROFILE) -> bool:
        """Delete a key. Returns True if the key existed."""
        return self._storage(profile).delete(key)

    def list(self, prefix: str = "", *, profile: str = _DEFAULT_PROFILE) -> builtins.list[str]:
        """List all keys matching a prefix."""
        return self._storage(profile).list_keys(prefix)

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def init(self) -> None:
        """
        Initialize the authsome directory structure.

        Creates ~/.authsome/, providers/, profiles/default/, and generates
        the master key if it does not already exist.
        """
        self._home.mkdir(parents=True, exist_ok=True)
        (self._home / "providers").mkdir(parents=True, exist_ok=True)
        (self._home / "profiles" / _DEFAULT_PROFILE).mkdir(parents=True, exist_ok=True)

        # Touch master key (lazy init triggers key generation)
        _ = self.crypto
        logger.info("Vault initialized at %s", self._home)

    def ensure_profile(self, profile: str) -> None:
        """Create a profile directory if it does not exist."""
        (self._home / "profiles" / profile).mkdir(parents=True, exist_ok=True)

    def profile_exists(self, profile: str) -> bool:
        return (self._home / "profiles" / profile).exists()

    def list_profile_dirs(self) -> builtins.list[Path]:
        profiles_dir = self._home / "profiles"
        if not profiles_dir.exists():
            return []
        return sorted(p for p in profiles_dir.iterdir() if p.is_dir())

    def close(self) -> None:
        """Close all open storage connections."""
        for store in self._stores.values():
            store.close()
        self._stores.clear()

    def __enter__(self) -> Vault:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── Internal ──────────────────────────────────────────────────────────

    def _storage(self, profile: str) -> SQLiteStorage:
        if profile not in self._stores:
            profile_dir = self._home / "profiles" / profile
            if not profile_dir.exists():
                from authsome.errors import ProfileNotFoundError

                raise ProfileNotFoundError(profile)
            self._stores[profile] = SQLiteStorage(profile_dir)
        return self._stores[profile]
