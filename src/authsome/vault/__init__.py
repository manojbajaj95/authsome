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
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from authsome.vault.storage import SQLiteStorage

if TYPE_CHECKING:
    from authsome.vault.crypto import VaultCrypto

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
        storage_resolver: Callable[[str], SQLiteStorage],
        crypto: VaultCrypto | None = None,
        crypto_mode: str = "local_key",
        master_key_path: Path | None = None,
    ) -> None:
        self._storage_resolver = storage_resolver
        self._crypto = crypto
        self._crypto_mode = crypto_mode
        self._master_key_path = master_key_path
        self._stores: dict[str, SQLiteStorage] = {}

    # ── Core KV interface ─────────────────────────────────────────────────

    @property
    def crypto(self) -> VaultCrypto:
        if self._crypto is None:
            from authsome.vault.crypto import create_crypto

            self._crypto = create_crypto(self._master_key_path, self._crypto_mode)
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
            self._stores[profile] = self._storage_resolver(profile)
        return self._stores[profile]
