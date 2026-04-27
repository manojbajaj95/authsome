"""Vault encryption backends.

The vault uses AES-256-GCM to encrypt record blobs at rest.
The compact wire format is: base64(nonce) + "." + base64(ciphertext || tag)

Two backends are available:
- LocalFileCrypto: master key stored in ~/.authsome/master.key (mode 0600)
- KeyringCrypto: master key stored in the OS keyring
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loguru import logger

from authsome.errors import EncryptionUnavailableError

_KEY_SIZE_BYTES = 32  # 256-bit
_NONCE_SIZE_BYTES = 12  # 96-bit for AES-GCM
_KEYRING_SERVICE = "authsome"
_KEYRING_USERNAME = "master_key"


class VaultCrypto(ABC):
    """Protocol for vault-level encryption backends."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return a compact ciphertext string."""
        ...

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a compact ciphertext string and return plaintext."""
        ...


def _encode(nonce: bytes, ct_with_tag: bytes) -> str:
    """Pack nonce + ciphertext+tag into a single dot-separated base64 string."""
    return base64.b64encode(nonce).decode("ascii") + "." + base64.b64encode(ct_with_tag).decode("ascii")


def _decode(token: str) -> tuple[bytes, bytes]:
    """Unpack a dot-separated base64 string into (nonce, ciphertext+tag)."""
    try:
        nonce_b64, ct_b64 = token.split(".", 1)
        return base64.b64decode(nonce_b64), base64.b64decode(ct_b64)
    except Exception as exc:
        raise EncryptionUnavailableError(f"Malformed vault ciphertext: {exc}") from exc


class LocalFileCrypto(VaultCrypto):
    """AES-256-GCM with master key stored as a local file."""

    def __init__(self, key_file: Path) -> None:
        self._key_file = key_file
        self._aesgcm = self._load_or_create()

    def _load_or_create(self) -> AESGCM:
        if self._key_file.exists():
            try:
                key_data = json.loads(self._key_file.read_text(encoding="utf-8"))
                master_key = base64.b64decode(key_data["key"])
                return AESGCM(master_key)
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise EncryptionUnavailableError(f"Failed to read local key file {self._key_file}: {exc}") from exc

        master_key = secrets.token_bytes(_KEY_SIZE_BYTES)
        self._key_file.parent.mkdir(parents=True, exist_ok=True)
        key_data = {
            "version": 1,
            "key": base64.b64encode(master_key).decode("ascii"),
            "algorithm": "AES-256-GCM",
            "note": "Local master key for authsome. Protect this file.",
        }
        self._key_file.write_text(json.dumps(key_data, indent=2), encoding="utf-8")
        try:
            os.chmod(self._key_file, 0o600)
        except OSError:
            pass
        logger.info("Generated new master key at {}", self._key_file)
        return AESGCM(master_key)

    def encrypt(self, plaintext: str) -> str:
        nonce = secrets.token_bytes(_NONCE_SIZE_BYTES)
        ct_with_tag = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return _encode(nonce, ct_with_tag)

    def decrypt(self, ciphertext: str) -> str:
        nonce, ct_with_tag = _decode(ciphertext)
        try:
            return self._aesgcm.decrypt(nonce, ct_with_tag, None).decode("utf-8")
        except Exception as exc:
            raise EncryptionUnavailableError(f"Decryption failed: {exc}") from exc


class KeyringCrypto(VaultCrypto):
    """AES-256-GCM with master key stored in the OS keyring."""

    def __init__(self) -> None:
        self._aesgcm = self._load_or_create()

    def _load_or_create(self) -> AESGCM:
        try:
            import keyring as kr
        except ImportError as exc:
            raise EncryptionUnavailableError(
                "The 'keyring' package is required for keyring mode. Install it with: pip install keyring"
            ) from exc

        try:
            key_b64 = kr.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        except Exception as exc:
            raise EncryptionUnavailableError(
                f"Failed to access OS keyring: {exc}. Use encryption mode 'local_key' for headless environments."
            ) from exc

        if key_b64:
            return AESGCM(base64.b64decode(key_b64))

        master_key = secrets.token_bytes(_KEY_SIZE_BYTES)
        key_b64_str = base64.b64encode(master_key).decode("ascii")
        try:
            kr.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, key_b64_str)
        except Exception as exc:
            raise EncryptionUnavailableError(
                f"Failed to store master key in OS keyring: {exc}. "
                "Use encryption mode 'local_key' for headless environments."
            ) from exc
        logger.info("Generated and stored new master key in OS keyring")
        return AESGCM(master_key)

    def encrypt(self, plaintext: str) -> str:
        nonce = secrets.token_bytes(_NONCE_SIZE_BYTES)
        ct_with_tag = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return _encode(nonce, ct_with_tag)

    def decrypt(self, ciphertext: str) -> str:
        nonce, ct_with_tag = _decode(ciphertext)
        try:
            return self._aesgcm.decrypt(nonce, ct_with_tag, None).decode("utf-8")
        except Exception as exc:
            raise EncryptionUnavailableError(f"Decryption failed: {exc}") from exc


def create_crypto(key_file: Path | None, mode: str = "local_key") -> VaultCrypto:
    """Factory: return the appropriate VaultCrypto backend for the given mode."""
    if mode == "keyring":
        return KeyringCrypto()
    if key_file is None:
        raise ValueError("key_file is required for 'local_key' mode")
    return LocalFileCrypto(key_file)
