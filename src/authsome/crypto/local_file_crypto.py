"""Local file-backed AES-256-GCM encryption backend.

Spec §10.5 option 2: A local wrapped key stored under ~/.authsome/.
Best for headless environments, CI, or systems without an OS keyring.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from authsome.crypto.base import CryptoBackend
from authsome.errors import EncryptionUnavailableError
from authsome.models.connection import EncryptedField

logger = logging.getLogger(__name__)

_KEY_SIZE_BYTES = 32  # 256-bit
_NONCE_SIZE_BYTES = 12  # 96-bit for AES-GCM


class LocalFileCryptoBackend(CryptoBackend):
    """
    AES-256-GCM encryption backend with master key stored as a local file.

    The master key is stored in <authsome_home>/master.key as a JSON file
    with restricted file permissions (0o600).

    Use this for headless environments, containers, or CI where no OS keyring
    is available.
    """

    def __init__(self, authsome_home: Path) -> None:
        self._authsome_home = authsome_home
        self._key_file = authsome_home / "master.key"
        self._master_key: bytes | None = None
        self._aesgcm: AESGCM | None = None
        self._load_or_create_key()

    def _load_or_create_key(self) -> None:
        """Load master key from local file, or generate and store a new one."""
        if self._key_file.exists():
            try:
                key_data = json.loads(self._key_file.read_text(encoding="utf-8"))
                self._master_key = base64.b64decode(key_data["key"])
                self._aesgcm = AESGCM(self._master_key)
                logger.debug("Master key loaded from local file")
                return
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                raise EncryptionUnavailableError(f"Failed to read local key file {self._key_file}: {exc}") from exc

        # Generate new key
        self._master_key = secrets.token_bytes(_KEY_SIZE_BYTES)
        self._aesgcm = AESGCM(self._master_key)
        key_b64 = base64.b64encode(self._master_key).decode("ascii")

        # Store to file
        self._authsome_home.mkdir(parents=True, exist_ok=True)
        key_data = {
            "version": 1,
            "key": key_b64,
            "algorithm": "AES-256-GCM",
            "note": "Local master key for authsome. Protect this file.",
        }
        self._key_file.write_text(json.dumps(key_data, indent=2), encoding="utf-8")

        # Restrict file permissions on Unix
        try:
            os.chmod(self._key_file, 0o600)
        except OSError:
            pass  # Windows or restrictive environments

        logger.info("Generated and stored new master key at %s", self._key_file)

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
