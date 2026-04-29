"""Tests for authentication flows."""

import pytest

from authsome.auth.flows.api_key import ApiKeyFlow
from authsome.auth.models.enums import AuthType, ConnectionStatus, FlowType
from authsome.auth.models.provider import ApiKeyConfig, ProviderDefinition
from authsome.errors import AuthenticationFailedError


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

    def test_successful_login(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        result = flow.authenticate(
            provider=provider,
            profile="default",
            connection_name="default",
            api_key="sk-test-key-123",
        )
        record = result.connection

        assert record.provider == "testapi"
        assert record.profile == "default"
        assert record.connection_name == "default"
        assert record.auth_type == AuthType.API_KEY
        assert record.status == ConnectionStatus.CONNECTED
        # Token is stored as plaintext
        assert record.api_key == "sk-test-key-123"
        assert record.schema_version == 2

    def test_empty_key_rejected(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        with pytest.raises(AuthenticationFailedError, match="cannot be empty"):
            flow.authenticate(
                provider=provider,
                profile="default",
                connection_name="default",
                api_key="",
            )

    def test_whitespace_only_rejected(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        with pytest.raises(AuthenticationFailedError, match="cannot be empty"):
            flow.authenticate(
                provider=provider,
                profile="default",
                connection_name="default",
                api_key="   ",
            )

    def test_missing_api_key_config(self) -> None:
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
                profile="default",
                connection_name="default",
                api_key="sk-test-key-123",
            )

    def test_missing_api_key_parameter(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        with pytest.raises(AuthenticationFailedError, match="cannot be empty"):
            flow.authenticate(
                provider=provider,
                profile="default",
                connection_name="default",
                api_key=None,
            )

    def test_api_key_stripped(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()

        result = flow.authenticate(
            provider=provider,
            profile="default",
            connection_name="default",
            api_key="  sk-test-key-123  ",
        )
        assert result.connection.api_key == "sk-test-key-123"

    def test_key_pattern_match_succeeds(self) -> None:
        flow = ApiKeyFlow()
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(
                key_pattern=r"^sk-[A-Za-z0-9_-]{8,}$",
                key_pattern_hint="Keys start with 'sk-'.",
            ),
        )

        result = flow.authenticate(
            provider=provider,
            profile="default",
            connection_name="default",
            api_key="sk-abcdefgh12345",
        )
        assert result.connection.api_key == "sk-abcdefgh12345"

    def test_key_pattern_mismatch_uses_hint(self) -> None:
        flow = ApiKeyFlow()
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(
                key_pattern=r"^sk-[A-Za-z0-9_-]{8,}$",
                key_pattern_hint="Keys start with 'sk-'.",
            ),
        )

        with pytest.raises(AuthenticationFailedError, match="Keys start with 'sk-'"):
            flow.authenticate(
                provider=provider,
                profile="default",
                connection_name="default",
                api_key="982832",
            )

    def test_key_pattern_mismatch_default_message(self) -> None:
        flow = ApiKeyFlow()
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(key_pattern=r"^sk-.+$"),
        )

        with pytest.raises(AuthenticationFailedError, match="doesn't match the expected format"):
            flow.authenticate(
                provider=provider,
                profile="default",
                connection_name="default",
                api_key="982832",
            )

    def test_no_pattern_skips_validation(self) -> None:
        flow = ApiKeyFlow()
        provider = _make_api_key_provider()  # no key_pattern

        result = flow.authenticate(
            provider=provider,
            profile="default",
            connection_name="default",
            api_key="982832",
        )
        assert result.connection.api_key == "982832"
