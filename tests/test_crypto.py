"""Tests for the crypto layer."""

import sys
import types
import json
from pathlib import Path

import pytest

from authsome.crypto.keyring_crypto import KeyringCryptoBackend
from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
from authsome.errors import EncryptionUnavailableError
from authsome.models.connection import EncryptedField


class TestLocalFileCryptoBackend:
    """Local file crypto backend tests."""

    @pytest.fixture
    def crypto(self, tmp_path: Path) -> LocalFileCryptoBackend:
        """Create a crypto backend using a temp directory."""
        return LocalFileCryptoBackend(tmp_path)

    def test_encrypt_returns_envelope(self, crypto: LocalFileCryptoBackend) -> None:
        field = crypto.encrypt("my-secret-token")
        assert isinstance(field, EncryptedField)
        assert field.enc == 1
        assert field.alg == "AES-256-GCM"
        assert field.kid == "local"
        assert len(field.nonce) > 0
        assert len(field.ciphertext) > 0
        assert len(field.tag) > 0

    def test_decrypt_roundtrip(self, crypto: LocalFileCryptoBackend) -> None:
        original = "sk-1234567890abcdef"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_empty_string(self, crypto: LocalFileCryptoBackend) -> None:
        original = ""
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_unicode(self, crypto: LocalFileCryptoBackend) -> None:
        original = "secret-🔑-тест-密钥"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_different_encryptions_differ(self, crypto: LocalFileCryptoBackend) -> None:
        """Different encrypt calls should produce different nonces/ciphertexts."""
        e1 = crypto.encrypt("same-value")
        e2 = crypto.encrypt("same-value")
        assert e1.nonce != e2.nonce or e1.ciphertext != e2.ciphertext

    def test_key_persistence(self, tmp_path: Path) -> None:
        """A second backend instance should decrypt what the first encrypted."""
        crypto1 = LocalFileCryptoBackend(tmp_path)
        encrypted = crypto1.encrypt("persist-test")

        crypto2 = LocalFileCryptoBackend(tmp_path)
        decrypted = crypto2.decrypt(encrypted)
        assert decrypted == "persist-test"

    def test_master_key_file_created(self, tmp_path: Path) -> None:
        """Master key file should be created."""
        _ = LocalFileCryptoBackend(tmp_path)
        key_file = tmp_path / "master.key"
        assert key_file.exists()

    def test_long_token_roundtrip(self, crypto: LocalFileCryptoBackend) -> None:
        original = "a" * 10000
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_rejects_wrong_algorithm(self, crypto: LocalFileCryptoBackend) -> None:
        field = crypto.encrypt("secret")
        field.alg = "XChaCha20-Poly1305"

        with pytest.raises(EncryptionUnavailableError, match="Unsupported algorithm"):
            crypto.decrypt(field)

    def test_invalid_key_file_raises(self, tmp_path: Path) -> None:
        key_file = tmp_path / "master.key"
        key_file.write_text(json.dumps({"version": 1, "key": "not-base64"}), encoding="utf-8")

        with pytest.raises(EncryptionUnavailableError, match="Failed to read local key file"):
            LocalFileCryptoBackend(tmp_path)


class TestKeyringCryptoBackend:
    """OS Keyring crypto backend tests.

    These tests attempt to use the real OS keyring. They may be skipped
    in headless CI environments where no keyring backend is available.
    """

    @pytest.fixture
    def crypto(self) -> KeyringCryptoBackend:
        """Create a keyring crypto backend."""
        try:
            return KeyringCryptoBackend()
        except Exception:
            pytest.skip("OS keyring not available in this environment")

    def test_encrypt_decrypt_roundtrip(self, crypto: KeyringCryptoBackend) -> None:
        original = "keyring-test-secret"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_envelope_format(self, crypto: KeyringCryptoBackend) -> None:
        field = crypto.encrypt("test")
        assert field.enc == 1
        assert field.alg == "AES-256-GCM"
        assert field.kid == "local"


class TestCrossBackendCompatibility:
    """Verify that both backends produce compatible envelope formats."""

    def test_same_envelope_structure(self, tmp_path: Path) -> None:
        """Both backends should produce the same EncryptedField structure."""
        local = LocalFileCryptoBackend(tmp_path)
        field = local.encrypt("test")

        assert hasattr(field, "enc")
        assert hasattr(field, "alg")
        assert hasattr(field, "kid")
        assert hasattr(field, "nonce")
        assert hasattr(field, "ciphertext")
        assert hasattr(field, "tag")
        assert field.alg == "AES-256-GCM"


class TestKeyringBackendIsolation:
    """Isolated keyring module behavior without relying on a system backend."""

    def test_load_existing_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key_b64 = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
        fake_keyring = types.ModuleType("keyring")
        fake_keyring.get_password = lambda service, username: key_b64  # type: ignore[attr-defined]
        fake_keyring.set_password = lambda *args, **kwargs: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

        crypto = KeyringCryptoBackend()
        encrypted = crypto.encrypt("roundtrip")
        assert crypto.decrypt(encrypted) == "roundtrip"

    def test_generate_new_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[tuple] = []
        fake_keyring = types.ModuleType("keyring")
        fake_keyring.get_password = lambda service, username: None  # type: ignore[attr-defined]

        def set_password(service, username, value):
            calls.append((service, username, value))

        fake_keyring.set_password = set_password  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

        crypto = KeyringCryptoBackend()
        assert calls and calls[0][0] == "authsome"
        assert crypto.decrypt(crypto.encrypt("generated")) == "generated"

    def test_get_password_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_keyring = types.ModuleType("keyring")

        def get_password(service, username):
            raise RuntimeError("boom")

        fake_keyring.get_password = get_password  # type: ignore[attr-defined]
        fake_keyring.set_password = lambda *args, **kwargs: None  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

        with pytest.raises(EncryptionUnavailableError, match="Failed to access OS keyring"):
            KeyringCryptoBackend()

    def test_set_password_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake_keyring = types.ModuleType("keyring")
        fake_keyring.get_password = lambda service, username: None  # type: ignore[attr-defined]

        def set_password(service, username, value):
            raise RuntimeError("boom")

        fake_keyring.set_password = set_password  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "keyring", fake_keyring)

        with pytest.raises(EncryptionUnavailableError, match="Failed to store master key in OS keyring"):
            KeyringCryptoBackend()
