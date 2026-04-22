"""Tests for authentication flows."""

from pathlib import Path

import pytest

from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
from authsome.errors import AuthenticationFailedError
from authsome.flows.api_key import ApiKeyFlow
from authsome.models.enums import AuthType, ConnectionStatus, FlowType
from authsome.models.provider import ApiKeyConfig, ProviderDefinition


def _make_api_key_provider() -> ProviderDefinition:
    return ProviderDefinition(
        name="testapi",
        display_name="Test API",
        auth_type=AuthType.API_KEY,
        flow=FlowType.API_KEY,
        api_key=ApiKeyConfig(
            header_name="Authorization",
            header_prefix="Bearer",
        ),
    )


class TestApiKeyFlow:
    """API key flow tests."""

    @pytest.fixture
    def crypto(self, tmp_path: Path) -> LocalFileCryptoBackend:
        return LocalFileCryptoBackend(tmp_path)

    def test_successful_login(self, crypto: LocalFileCryptoBackend) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        record = flow.authenticate(
            provider=provider,
            crypto=crypto,
            profile="default",
            connection_name="default",
            api_key="sk-test-key-123",
        )

        assert record.provider == "testapi"
        assert record.profile == "default"
        assert record.connection_name == "default"
        assert record.auth_type == AuthType.API_KEY
        assert record.status == ConnectionStatus.CONNECTED
        assert record.api_key is not None
        # Verify the encrypted key can be decrypted
        decrypted = crypto.decrypt(record.api_key)
        assert decrypted == "sk-test-key-123"

    def test_empty_key_rejected(self, crypto: LocalFileCryptoBackend) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        with pytest.raises(AuthenticationFailedError, match="not provided"):
            flow.authenticate(
                provider=provider,
                crypto=crypto,
                profile="default",
                connection_name="default",
                api_key="",
            )

    def test_whitespace_only_rejected(self, crypto: LocalFileCryptoBackend) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        with pytest.raises(AuthenticationFailedError, match="cannot be empty"):
            flow.authenticate(
                provider=provider,
                crypto=crypto,
                profile="default",
                connection_name="default",
                api_key="   ",
            )

    def test_missing_api_key_config(self, crypto: LocalFileCryptoBackend) -> None:
        flow = ApiKeyFlow()
        provider = ProviderDefinition(
            name="noconfig",
            display_name="No Config",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
        )
        with pytest.raises(AuthenticationFailedError, match="missing 'api_key'"):
            flow.authenticate(
                provider=provider,
                crypto=crypto,
                profile="default",
                connection_name="default",
                api_key="sk-test-key",
            )
