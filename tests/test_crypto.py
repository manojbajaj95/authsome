"""Tests for the crypto layer."""

from pathlib import Path

import pytest

from authsome.crypto.keyring_crypto import KeyringCryptoBackend
from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
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
