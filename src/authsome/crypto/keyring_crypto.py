"""OS Keyring-backed AES-256-GCM encryption backend.

Spec §10.5 option 1: Uses OS keychain/credential manager to store the master key.
The master key never touches the filesystem.
"""

from __future__ import annotations

import base64
import logging
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from authsome.crypto.base import CryptoBackend
from authsome.errors import EncryptionUnavailableError
from authsome.models.connection import EncryptedField

logger = logging.getLogger(__name__)

_KEYRING_SERVICE = "authsome"
_KEYRING_USERNAME = "master_key"
_KEY_SIZE_BYTES = 32  # 256-bit
_NONCE_SIZE_BYTES = 12  # 96-bit for AES-GCM


class KeyringCryptoBackend(CryptoBackend):
    """
    AES-256-GCM encryption backend with master key stored in the OS keyring.

    The master key is stored exclusively in the OS credential manager
    (macOS Keychain, GNOME Keyring, Windows Credential Locker, etc.).

    Use this when a graphical desktop environment or credential agent is available.
    """

    def __init__(self) -> None:
        self._master_key: bytes | None = None
        self._aesgcm: AESGCM | None = None
        self._load_or_create_key()

    def _load_or_create_key(self) -> None:
        """Load master key from OS keyring, or generate and store a new one."""
        try:
            import keyring as kr
        except ImportError as exc:
            raise EncryptionUnavailableError(
                "The 'keyring' package is required for keyring encryption mode. Install it with: pip install keyring"
            ) from exc

        # Try loading existing key
        try:
            key_b64 = kr.get_password(_KEYRING_SERVICE, _KEYRING_USERNAME)
        except Exception as exc:
            raise EncryptionUnavailableError(
                f"Failed to access OS keyring: {exc}. "
                "Use encryption mode 'local_key' for environments without a keyring."
            ) from exc

        if key_b64:
            self._master_key = base64.b64decode(key_b64)
            self._aesgcm = AESGCM(self._master_key)
            logger.debug("Master key loaded from OS keyring")
            return

        # Generate new key and store
        self._master_key = secrets.token_bytes(_KEY_SIZE_BYTES)
        self._aesgcm = AESGCM(self._master_key)
        key_b64_str = base64.b64encode(self._master_key).decode("ascii")

        try:
            kr.set_password(_KEYRING_SERVICE, _KEYRING_USERNAME, key_b64_str)
            logger.info("Generated and stored new master key in OS keyring")
        except Exception as exc:
            raise EncryptionUnavailableError(
                f"Failed to store master key in OS keyring: {exc}. "
                "Use encryption mode 'local_key' for environments without a keyring."
            ) from exc

    def encrypt(self, plaintext: str) -> EncryptedField:
        """Encrypt a plaintext string using AES-256-GCM."""
        if self._aesgcm is None or self._master_key is None:
            raise EncryptionUnavailableError("Master key not initialized")

        nonce = secrets.token_bytes(_NONCE_SIZE_BYTES)
        plaintext_bytes = plaintext.encode("utf-8")

        ct_with_tag = self._aesgcm.encrypt(nonce, plaintext_bytes, None)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        return EncryptedField(
            enc=1,
            alg="AES-256-GCM",
            kid="local",
            nonce=base64.b64encode(nonce).decode("ascii"),
            ciphertext=base64.b64encode(ciphertext).decode("ascii"),
            tag=base64.b64encode(tag).decode("ascii"),
        )

    def decrypt(self, field: EncryptedField) -> str:
        """Decrypt an encrypted field envelope."""
        if self._aesgcm is None or self._master_key is None:
            raise EncryptionUnavailableError("Master key not initialized")

        if field.alg != "AES-256-GCM":
            raise EncryptionUnavailableError(f"Unsupported algorithm: {field.alg}")

        try:
            nonce = base64.b64decode(field.nonce)
            ciphertext = base64.b64decode(field.ciphertext)
            tag = base64.b64decode(field.tag)
        except Exception as exc:
            raise EncryptionUnavailableError(f"Failed to decode envelope: {exc}") from exc

        ct_with_tag = ciphertext + tag

        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, ct_with_tag, None)
        except Exception as exc:
            raise EncryptionUnavailableError(f"Decryption failed: {exc}") from exc

        return plaintext_bytes.decode("utf-8")
