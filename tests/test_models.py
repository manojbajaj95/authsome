"""Tests for authsome data models."""

from authsome.models.config import GlobalConfig
from authsome.models.connection import (
    ConnectionRecord,
    EncryptedField,
    ProviderMetadataRecord,
    ProviderStateRecord,
)
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.profile import ProfileMetadata
from authsome.models.provider import ApiKeyConfig, OAuthConfig, ProviderDefinition


class TestEnums:
    """Enum serialization and values."""

    def test_auth_type_values(self) -> None:
        assert AuthType.OAUTH2.value == "oauth2"
        assert AuthType.API_KEY.value == "api_key"

    def test_flow_type_values(self) -> None:
        assert FlowType.DCR_PKCE.value == "dcr_pkce"
        assert FlowType.API_KEY.value == "api_key"

    def test_connection_status_values(self) -> None:
        assert ConnectionStatus.CONNECTED.value == "connected"
        assert ConnectionStatus.EXPIRED.value == "expired"
        assert ConnectionStatus.REVOKED.value == "revoked"

    def test_export_format_values(self) -> None:
        assert ExportFormat.ENV.value == "env"
        assert ExportFormat.SHELL.value == "shell"
        assert ExportFormat.JSON.value == "json"


class TestGlobalConfig:
    """Global config model tests."""

    def test_defaults(self) -> None:
        config = GlobalConfig()
        assert config.spec_version == 1
        assert config.default_profile == "default"
        assert config.encryption is not None
        assert config.encryption.mode == "local_key"

    def test_json_roundtrip(self) -> None:
        config = GlobalConfig(spec_version=1, default_profile="work")
        json_str = config.model_dump_json()
        restored = GlobalConfig.model_validate_json(json_str)
        assert restored.default_profile == "work"

    def test_extra_fields_preserved(self) -> None:
        config = GlobalConfig.model_validate({"spec_version": 1, "default_profile": "x", "custom": "val"})
        dumped = config.model_dump()
        assert dumped.get("custom") == "val"


class TestProfileMetadata:
    """Profile metadata model tests."""

    def test_required_fields(self) -> None:
        meta = ProfileMetadata(name="test")
        assert meta.name == "test"
        assert meta.created_at is not None
        assert meta.updated_at is not None

    def test_json_roundtrip(self) -> None:
        meta = ProfileMetadata(
            name="work",
            description="Work profile",
        )
        json_str = meta.model_dump_json()
        restored = ProfileMetadata.model_validate_json(json_str)
        assert restored.name == "work"
        assert restored.description == "Work profile"


class TestProviderDefinition:
    """Provider definition model tests."""

    def test_oauth_provider(self) -> None:
        provider = ProviderDefinition(
            name="github",
            display_name="GitHub",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(
                authorization_url="https://github.com/login/oauth/authorize",
                token_url="https://github.com/login/oauth/access_token",
                scopes=["repo", "read:user"],
            ),
        )
        assert provider.auth_type == AuthType.OAUTH2
        assert provider.flow == FlowType.DCR_PKCE
        assert provider.oauth is not None
        assert "repo" in provider.oauth.scopes

    def test_api_key_provider(self) -> None:
        provider = ProviderDefinition(
            name="openai",
            display_name="OpenAI",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(
                header_name="Authorization",
                header_prefix="Bearer",
            ),
        )
        assert provider.auth_type == AuthType.API_KEY
        assert provider.api_key is not None

    def test_json_roundtrip(self) -> None:
        provider = ProviderDefinition(
            name="test",
            display_name="Test",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(),
        )
        json_str = provider.model_dump_json()
        restored = ProviderDefinition.model_validate_json(json_str)
        assert restored.name == "test"


class TestEncryptedField:
    """Encrypted field envelope model tests."""

    def test_structure(self) -> None:
        field = EncryptedField(
            nonce="bm9uY2U=",
            ciphertext="Y2lwaGVy",
            tag="dGFn",
        )
        assert field.enc == 1
        assert field.alg == "AES-256-GCM"
        assert field.kid == "local"

    def test_json_roundtrip(self) -> None:
        field = EncryptedField(nonce="a", ciphertext="b", tag="c")
        json_str = field.model_dump_json()
        restored = EncryptedField.model_validate_json(json_str)
        assert restored.nonce == "a"


class TestConnectionRecord:
    """Connection record model tests."""

    def test_oauth_record(self) -> None:
        record = ConnectionRecord(
            provider="github",
            profile="default",
            connection_name="personal",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            scopes=["repo"],
            token_type="Bearer",
        )
        assert record.provider == "github"
        assert record.status == ConnectionStatus.CONNECTED

    def test_api_key_record(self) -> None:
        record = ConnectionRecord(
            provider="openai",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
        )
        assert record.auth_type == AuthType.API_KEY

    def test_json_roundtrip_with_encrypted_fields(self) -> None:
        enc = EncryptedField(nonce="n", ciphertext="c", tag="t")
        record = ConnectionRecord(
            provider="test",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=enc,
        )
        json_str = record.model_dump_json()
        restored = ConnectionRecord.model_validate_json(json_str)
        assert restored.access_token is not None
        assert restored.access_token.nonce == "n"


class TestProviderMetadataRecord:
    """Provider metadata record tests."""

    def test_defaults(self) -> None:
        meta = ProviderMetadataRecord(profile="default", provider="github")
        assert meta.default_connection == "default"
        assert meta.connection_names == []

    def test_connection_tracking(self) -> None:
        meta = ProviderMetadataRecord(
            profile="default",
            provider="github",
            connection_names=["personal", "work"],
            last_used_connection="work",
        )
        assert len(meta.connection_names) == 2
        assert meta.last_used_connection == "work"


class TestProviderStateRecord:
    """Provider state record tests."""

    def test_defaults(self) -> None:
        state = ProviderStateRecord(provider="github", profile="default")
        assert state.last_refresh_at is None
        assert state.last_refresh_error is None


class TestHostUrl:
    """ProviderDefinition host_url field tests."""

    def test_provider_definition_parses_host_url(self) -> None:
        provider = ProviderDefinition.model_validate(
            {
                "schema_version": 1,
                "name": "openai",
                "display_name": "OpenAI",
                "auth_type": "api_key",
                "flow": "api_key",
                "api_key": {"header_name": "Authorization", "header_prefix": "Bearer"},
                "host_url": "api.openai.com",
            }
        )

        assert provider.host_url == "api.openai.com"

    def test_provider_definition_defaults_host_url_to_none(self) -> None:
        provider = ProviderDefinition.model_validate(
            {
                "schema_version": 1,
                "name": "example",
                "display_name": "Example",
                "auth_type": "api_key",
                "flow": "api_key",
                "api_key": {"header_name": "Authorization", "header_prefix": "Bearer"},
            }
        )

        assert provider.host_url is None
