"""Tests for the vault crypto layer."""

from pathlib import Path

import pytest

from authsome.vault.crypto import KeyringCrypto, LocalFileCrypto, _decode, _encode


class TestLocalFileCrypto:
    """Local file crypto backend tests."""

    @pytest.fixture
    def crypto(self, tmp_path: Path) -> LocalFileCrypto:
        return LocalFileCrypto(tmp_path / "master.key")

    def test_encrypt_returns_string(self, crypto: LocalFileCrypto) -> None:
        result = crypto.encrypt("my-secret-token")
        assert isinstance(result, str)
        assert "." in result  # compact format: nonce.ciphertext+tag

    def test_decrypt_roundtrip(self, crypto: LocalFileCrypto) -> None:
        original = "sk-1234567890abcdef"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_empty_string(self, crypto: LocalFileCrypto) -> None:
        original = ""
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_decrypt_unicode(self, crypto: LocalFileCrypto) -> None:
        original = "secret-🔑-тест-密钥"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_different_encryptions_differ(self, crypto: LocalFileCrypto) -> None:
        e1 = crypto.encrypt("same-value")
        e2 = crypto.encrypt("same-value")
        assert e1 != e2  # different nonces

    def test_key_persistence(self, tmp_path: Path) -> None:
        key_file = tmp_path / "master.key"
        crypto1 = LocalFileCrypto(key_file)
        encrypted = crypto1.encrypt("persist-test")

        crypto2 = LocalFileCrypto(key_file)
        decrypted = crypto2.decrypt(encrypted)
        assert decrypted == "persist-test"

    def test_master_key_file_created(self, tmp_path: Path) -> None:
        _ = LocalFileCrypto(tmp_path / "master.key")
        key_file = tmp_path / "master.key"
        assert key_file.exists()

    def test_long_token_roundtrip(self, crypto: LocalFileCrypto) -> None:
        original = "a" * 10000
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_json_load_error(self, tmp_path: Path) -> None:
        from authsome.errors import EncryptionUnavailableError

        key_file = tmp_path / "master.key"
        key_file.write_text("invalid json")
        with pytest.raises(EncryptionUnavailableError, match="Failed to read local key file"):
            LocalFileCrypto(tmp_path / "master.key")

    def test_chmod_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import os

        def mock_chmod(path, mode):
            raise OSError("Mock error")

        monkeypatch.setattr(os, "chmod", mock_chmod)
        # Should not raise
        _ = LocalFileCrypto(tmp_path / "master.key")

    def test_decrypt_malformed_ciphertext(self, crypto: LocalFileCrypto) -> None:
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError, match="Malformed vault ciphertext"):
            crypto.decrypt("no-dot-separator!!!")

    def test_decrypt_bad_base64(self, crypto: LocalFileCrypto) -> None:
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError):
            crypto.decrypt("!@#$.!@#$")

    def test_decrypt_wrong_data(self, crypto: LocalFileCrypto, tmp_path: Path) -> None:
        from authsome.errors import EncryptionUnavailableError

        # Encrypt with one key, try to decrypt with a different key instance
        other_crypto = LocalFileCrypto(tmp_path / "other" / "master.key")
        ct = other_crypto.encrypt("secret")
        with pytest.raises(EncryptionUnavailableError, match="Decryption failed"):
            crypto.decrypt(ct)


class TestKeyringCrypto:
    """OS Keyring crypto backend tests.

    These tests attempt to use the real OS keyring. They may be skipped
    in headless CI environments where no keyring backend is available.
    """

    @pytest.fixture
    def crypto(self) -> KeyringCrypto:
        try:
            return KeyringCrypto()
        except Exception:
            pytest.skip("OS keyring not available in this environment")

    def test_encrypt_decrypt_roundtrip(self, crypto: KeyringCrypto) -> None:
        original = "keyring-test-secret"
        encrypted = crypto.encrypt(original)
        decrypted = crypto.decrypt(encrypted)
        assert decrypted == original

    def test_encrypt_returns_string(self, crypto: KeyringCrypto) -> None:
        result = crypto.encrypt("test")
        assert isinstance(result, str)
        assert "." in result

    def test_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "keyring", None)
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError, match="The 'keyring' package is required"):
            KeyringCrypto()

    def test_get_password_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import keyring

        def mock_get(*args, **kwargs):
            raise Exception("Mock error")

        monkeypatch.setattr(keyring, "get_password", mock_get)
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError, match="Failed to access OS keyring"):
            KeyringCrypto()

    def test_generate_new_keyring_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import keyring

        def mock_get(*args, **kwargs):
            return None

        def mock_set(*args, **kwargs):
            pass

        monkeypatch.setattr(keyring, "get_password", mock_get)
        monkeypatch.setattr(keyring, "set_password", mock_set)
        backend = KeyringCrypto()
        assert backend._aesgcm is not None

    def test_set_password_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import keyring

        def mock_get(*args, **kwargs):
            return None

        def mock_set(*args, **kwargs):
            raise Exception("Mock error")

        monkeypatch.setattr(keyring, "get_password", mock_get)
        monkeypatch.setattr(keyring, "set_password", mock_set)
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError, match="Failed to store master key"):
            KeyringCrypto()


class TestVaultCryptoHelpers:
    """Test _encode/_decode helpers."""

    def test_encode_decode_roundtrip(self) -> None:
        nonce = b"\x00" * 12
        ct = b"\xff" * 32
        token = _encode(nonce, ct)
        assert "." in token
        decoded_nonce, decoded_ct = _decode(token)
        assert decoded_nonce == nonce
        assert decoded_ct == ct

    def test_decode_malformed_raises(self) -> None:
        from authsome.errors import EncryptionUnavailableError

        with pytest.raises(EncryptionUnavailableError, match="Malformed vault ciphertext"):
            _decode("no-dot-here")
