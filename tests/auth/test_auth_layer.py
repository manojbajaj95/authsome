"""Tests for the AuthLayer core."""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from authsome.auth import AuthLayer
from authsome.auth.input_provider import MockInputProvider
from authsome.auth.models.connection import ConnectionRecord, ProviderClientRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.auth.models.provider import ApiKeyConfig, ExportConfig, OAuthConfig, ProviderDefinition
from authsome.context import AuthsomeContext
from authsome.errors import (
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    ProviderNotFoundError,
    RefreshFailedError,
    TokenExpiredError,
    UnsupportedFlowError,
)
from authsome.utils import utc_now


@pytest.fixture
def auth(tmp_path: Path) -> AuthLayer:
    home = tmp_path / ".authsome"
    actx = AuthsomeContext.create(home=home)
    yield actx.auth
    actx.close()


class TestAuthLayerInit:
    """Initialization and directory setup tests."""

    def test_init_creates_structure(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        actx = AuthsomeContext.create(home=home)

        assert (home / "providers").is_dir()
        assert (home / "profiles" / "default").is_dir()
        assert (home / "profiles" / "default" / "metadata.json").exists()
        actx.close()

    def test_master_key_created(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        actx = AuthsomeContext.create(home=home)
        # Triggering encryption creates the key
        actx.vault.put("test", "test", profile="default")
        assert (home / "master.key").exists()
        actx.close()

    def test_vault_crypto_roundtrip(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        actx = AuthsomeContext.create(home=home)
        actx.vault.put("test:key", "secret", profile="default")
        assert actx.vault.get("test:key", profile="default") == "secret"
        actx.close()


class TestAuthLayerProviders:
    """Provider operations tests."""

    def test_list_providers_includes_bundled(self, auth: AuthLayer) -> None:
        providers = auth.list_providers()
        names = [p.name for p in providers]
        assert "openai" in names
        assert "github" in names

    def test_get_provider(self, auth: AuthLayer) -> None:
        provider = auth.get_provider("openai")
        assert provider.name == "openai"
        assert provider.auth_type == AuthType.API_KEY

    def test_get_nonexistent_provider(self, auth: AuthLayer) -> None:
        with pytest.raises(ProviderNotFoundError):
            auth.get_provider("nonexistent")

    def test_register_and_get_custom_provider(self, auth: AuthLayer) -> None:
        custom = ProviderDefinition(
            name="custom",
            display_name="Custom Provider",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(env_var="CUSTOM_KEY"),
        )
        auth.register_provider(custom)
        loaded = auth.get_provider("custom")
        assert loaded.display_name == "Custom Provider"

    def test_list_providers_by_source(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testlocal",
            display_name="Test Local",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "Authorization"},
        )
        auth.register_provider(provider)
        sources = auth.list_providers_by_source()
        assert "bundled" in sources
        assert "custom" in sources
        assert len(sources["custom"]) > 0


class TestAuthLayerProfiles:
    """Profile management tests."""

    def test_default_profile_created(self, auth: AuthLayer) -> None:
        profiles = auth.list_profiles()
        names = [p.name for p in profiles]
        assert "default" in names

    def test_create_profile(self, auth: AuthLayer) -> None:
        auth.create_profile("work", description="Work profile")
        profiles = auth.list_profiles()
        names = [p.name for p in profiles]
        assert "work" in names

    def test_list_profiles_no_dir(self, auth: AuthLayer) -> None:
        import shutil

        profiles_dir = auth._profiles_dir
        shutil.rmtree(profiles_dir)
        assert auth.list_profiles() == []


class TestAuthLayerLogin:
    """Authentication flow integration tests."""

    def test_api_key_login_and_get(self, auth: AuthLayer) -> None:
        record = auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-test-123-padded-for-regex"}))

        assert record.status == ConnectionStatus.CONNECTED
        assert record.auth_type == AuthType.API_KEY
        assert record.schema_version == 2

        conn = auth.get_connection("openai")
        assert conn.status == ConnectionStatus.CONNECTED

    def test_login_connection_exists(self, auth: AuthLayer) -> None:
        first = auth.login(
            "openai",
            "default",
            input_provider=MockInputProvider({"api_key": "sk-1-padded-for-regex-checking"}),
        )

        second = auth.login("openai", "default", force=False)
        assert second.api_key == "sk-1-padded-for-regex-checking"
        assert second.obtained_at == first.obtained_at

        forced = auth.login(
            "openai",
            "default",
            force=True,
            input_provider=MockInputProvider({"api_key": "sk-2-padded-for-regex-checking"}),
        )
        assert forced.api_key == "sk-2-padded-for-regex-checking"

    def test_login_with_result_marks_existing_valid_connection(self, auth: AuthLayer) -> None:
        auth.login(
            "openai",
            "default",
            input_provider=MockInputProvider({"api_key": "sk-1-padded-for-regex-checking"}),
        )

        result = auth.login_with_result("openai", "default")

        assert result.already_connected is True
        assert result.record.api_key == "sk-1-padded-for-regex-checking"

    def test_login_reauthenticates_expired_connection(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testoauth-expired",
            display_name="Test OAuth Expired",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)
        auth._save_provider_client_credentials(
            ProviderClientRecord(profile="default", provider="testoauth-expired", client_id="cid")
        )
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testoauth-expired",
                profile="default",
                connection_name="default",
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                access_token="old",
                expires_at=utc_now() - timedelta(seconds=1),
            )
        )

        replacement = ConnectionRecord(
            schema_version=2,
            provider="testoauth-expired",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="new",
            expires_at=utc_now() + timedelta(hours=1),
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=replacement)
            handlers.get.return_value = lambda: mock_handler

            result = auth.login_with_result("testoauth-expired", scopes=[])

        assert result.already_connected is False
        assert result.record.access_token == "new"
        mock_handler.authenticate.assert_called_once()

    @pytest.mark.skip(reason="Context reuse tests need a headless-safe flow harness.")
    def test_login_reuses_connection_when_requested_scopes_match(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth-scopes",
            display_name="Test OAuth Scopes",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testoauth-scopes",
                profile="default",
                connection_name="default",
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                access_token="old",
                scopes=["repo", "read:user"],
                expires_at=utc_now() + timedelta(hours=1),
            )
        )

        result = auth.login_with_result("testoauth-scopes", scopes=["read:user", "repo"])

        assert result.already_connected is True
        assert result.record.access_token == "old"

    @pytest.mark.skip(reason="Context reuse tests need a headless-safe flow harness.")
    def test_login_reauthenticates_when_requested_scopes_differ(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testoauth-scope-diff",
            display_name="Test OAuth Scope Diff",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)
        auth._save_provider_client_credentials(
            ProviderClientRecord(profile="default", provider="testoauth-scope-diff", client_id="cid")
        )
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testoauth-scope-diff",
                profile="default",
                connection_name="default",
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                access_token="old",
                scopes=["read"],
                expires_at=utc_now() + timedelta(hours=1),
            )
        )
        replacement = ConnectionRecord(
            schema_version=2,
            provider="testoauth-scope-diff",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="new",
            scopes=["write"],
            expires_at=utc_now() + timedelta(hours=1),
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=replacement)
            handlers.get.return_value = lambda: mock_handler

            result = auth.login_with_result("testoauth-scope-diff", scopes=["write"])

        assert result.already_connected is False
        assert result.record.access_token == "new"
        mock_handler.authenticate.assert_called_once()

    @pytest.mark.skip(reason="Context reuse tests need a headless-safe flow harness.")
    def test_login_reauthenticates_when_requested_base_url_differs(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testoauth-base-url",
            display_name="Test OAuth Base URL",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(
                base_url="https://github.com",
                authorization_url="{base_url}/login/oauth/authorize",
                token_url="{base_url}/login/oauth/access_token",
            ),
        )
        auth.register_provider(provider)
        auth._save_provider_client_credentials(
            ProviderClientRecord(profile="default", provider="testoauth-base-url", client_id="cid")
        )
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testoauth-base-url",
                profile="default",
                connection_name="default",
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                access_token="old",
                base_url="https://github.example.com",
                expires_at=utc_now() + timedelta(hours=1),
            )
        )
        replacement = ConnectionRecord(
            schema_version=2,
            provider="testoauth-base-url",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="new",
            base_url="https://other.example.com",
            expires_at=utc_now() + timedelta(hours=1),
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=replacement)
            handlers.get.return_value = lambda: mock_handler

            result = auth.login_with_result("testoauth-base-url", base_url="https://other.example.com/")

        assert result.already_connected is False
        assert result.record.access_token == "new"
        mock_handler.authenticate.assert_called_once()

    @pytest.mark.skip(reason="Context reuse tests need a headless-safe flow harness.")
    def test_login_reuses_connection_when_requested_base_url_matches(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth-base-url-match",
            display_name="Test OAuth Base URL Match",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(
                base_url="https://github.com",
                authorization_url="{base_url}/login/oauth/authorize",
                token_url="{base_url}/login/oauth/access_token",
            ),
        )
        auth.register_provider(provider)
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testoauth-base-url-match",
                profile="default",
                connection_name="default",
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                access_token="old",
                base_url="https://github.example.com",
                expires_at=utc_now() + timedelta(hours=1),
            )
        )

        result = auth.login_with_result("testoauth-base-url-match", base_url="https://GITHUB.example.com/")

        assert result.already_connected is True
        assert result.record.access_token == "old"

    def test_login_unsupported_flow(self, auth: AuthLayer) -> None:
        def mock_get_provider(name):
            mock_def = MagicMock()
            mock_def.flow = MagicMock(value="invalid_flow")
            return mock_def

        with patch.object(auth, "get_provider", mock_get_provider):
            with pytest.raises(UnsupportedFlowError):
                auth.login("test")

    def test_login_oauth_bridge_prompt(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="access_token_value",
        )

        collected: list[dict] = []

        class CapturingProvider:
            def collect(self, fields):
                result = {"client_id": "cid", "client_secret": "csec"}
                collected.append(result)
                return result

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=mock_record)
            handlers.get.return_value = lambda: mock_handler

            auth.login("testoauth", input_provider=CapturingProvider())
            assert len(collected) == 1

            creds = auth._get_provider_client_credentials("testoauth")
            assert creds.client_id == "cid"
            assert creds.client_secret == "csec"

    def test_login_dcr_metadata_extraction(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testdcr",
            display_name="Test DCR",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=2,
            provider="testdcr",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="access_token_value",
        )
        mock_client = ProviderClientRecord(
            schema_version=2,
            profile="default",
            provider="testdcr",
            client_id="cid",
            client_secret="csec",
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=mock_record, client_record=mock_client)
            handlers.get.return_value = lambda: mock_handler

            auth.login("testdcr", scopes=["test_scope"])

            creds = auth._get_provider_client_credentials("testdcr")
            assert creds.client_id == "cid"
            assert creds.client_secret == "csec"

    def test_login_dcr_metadata_extraction_no_secret(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition(
            name="testdcr2",
            display_name="Test DCR 2",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        auth.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=2,
            provider="testdcr2",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="access_token_value",
        )
        mock_client = ProviderClientRecord(
            schema_version=2,
            profile="default",
            provider="testdcr2",
            client_id="cid",
            client_secret=None,
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=mock_record, client_record=mock_client)
            handlers.get.return_value = lambda: mock_handler

            auth.login("testdcr2", scopes=["test_scope"])

            creds = auth._get_provider_client_credentials("testdcr2")
            assert creds.client_id == "cid"
            assert creds.client_secret is None

    def test_login_api_key_bridge_includes_docs_instructions(self, auth: AuthLayer) -> None:
        from authsome.auth.flows.base import FlowResult

        provider = ProviderDefinition.model_validate(
            {
                "name": "docsapi",
                "display_name": "Docs API",
                "auth_type": "api_key",
                "flow": "api_key",
                "api_key": {"header_name": "Authorization", "header_prefix": "Bearer"},
                "docs": "https://example.com/create-key",
            }
        )
        auth.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=2,
            provider="docsapi",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key="sk-123",
        )

        with patch("authsome.auth._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = FlowResult(connection=mock_record)
            handlers.get.return_value = lambda: mock_handler

            with patch("authsome.auth.BridgeInputProvider") as bridge_cls:
                bridge_instance = MagicMock()
                bridge_instance.collect.return_value = {"api_key": "sk-123"}
                bridge_cls.return_value = bridge_instance

                auth.login("docsapi")

                static_fields = bridge_cls.call_args.kwargs["static_fields"]
                assert len(static_fields) == 1
                assert static_fields[0]["type"] == "instructions"
                assert static_fields[0]["label"] == "Instructions"
                assert static_fields[0]["url"] == "https://example.com/create-key"


class TestAuthLayerCredentials:
    """Credential retrieval tests."""

    def test_api_key_get_access_token(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-test-456-padded-for-regex"}))

        token = auth.get_access_token("openai")
        assert token == "sk-test-456-padded-for-regex"

    def test_api_key_get_auth_headers(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-test-789-padded-for-regex"}))

        headers = auth.get_auth_headers("openai")
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer sk-test-789-padded-for-regex"

    def test_get_access_token_oauth(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)

        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="token123",
        )
        auth._save_connection(record)

        assert auth.get_access_token("testoauth") == "token123"

    def test_get_access_token_unsupported(self, auth: AuthLayer) -> None:
        mock_record = MagicMock()
        mock_record.auth_type = "UNKNOWN"

        with patch.object(auth, "get_connection", return_value=mock_record):
            with pytest.raises(CredentialMissingError, match="Unsupported auth type"):
                auth.get_access_token("test")

    def test_get_auth_headers_unsupported(self, auth: AuthLayer) -> None:
        mock_record = MagicMock()
        mock_record.auth_type = "UNKNOWN"

        with patch.object(auth, "get_provider"):
            with patch.object(auth, "get_connection", return_value=mock_record):
                with pytest.raises(CredentialMissingError, match="Cannot build headers"):
                    auth.get_auth_headers("test")

    def test_get_auth_headers_api_key_custom(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "X-API-KEY", "header_prefix": ""},
        )
        auth.register_provider(provider)
        record = ConnectionRecord(
            schema_version=2,
            provider="testapi",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key="key123",
        )
        auth._save_connection(record)

        headers = auth.get_auth_headers("testapi")
        assert headers["X-API-KEY"] == "key123"

    def test_get_auth_headers_oauth(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="oauth123",
        )
        auth._save_connection(record)

        headers = auth.get_auth_headers("testoauth")
        assert headers["Authorization"] == "Bearer oauth123"

    def test_get_api_key_missing(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="test",
            display_name="Test",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "Authorization"},
        )
        auth.register_provider(provider)
        record = ConnectionRecord(
            schema_version=2,
            provider="test",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
        )
        auth._save_connection(record)
        with pytest.raises(CredentialMissingError, match="No API key stored"):
            auth._get_api_key(record)


class TestAuthLayerTokenRefresh:
    """OAuth token refresh logic tests."""

    def test_oauth_token_refresh(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)

        now = utc_now()
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="old_acc",
            refresh_token="ref",
            expires_at=now - timedelta(seconds=10),
        )
        auth._save_connection(record)

        with pytest.raises(RefreshFailedError, match="No client_id"):
            auth.get_access_token("testoauth")

        auth._save_provider_client_credentials(
            ProviderClientRecord(
                profile="default",
                provider="testoauth",
                client_id="cid",
                client_secret="sec",
            )
        )

        mock_token_resp = MagicMock()
        mock_token_resp.json.return_value = {
            "access_token": "new_acc",
            "refresh_token": "new_ref",
            "expires_in": 3600,
        }

        with patch("authsome.auth.http_client.post", return_value=mock_token_resp):
            assert auth.get_access_token("testoauth") == "new_acc"

        record.expires_at = now - timedelta(seconds=10)
        auth._save_connection(record)
        with patch(
            "authsome.auth.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            with pytest.raises(RefreshFailedError):
                auth.get_access_token("testoauth")
        assert auth.get_connection("testoauth").status == ConnectionStatus.EXPIRED

    def test_oauth_refresh_failure_keeps_valid_cached_token_connected(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth-valid-fallback",
            display_name="Test OAuth Valid Fallback",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)
        auth._save_provider_client_credentials(
            ProviderClientRecord(
                profile="default",
                provider="testoauth-valid-fallback",
                client_id="cid",
                client_secret="sec",
            )
        )

        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth-valid-fallback",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="cached",
            refresh_token="ref",
            expires_at=utc_now() + timedelta(seconds=60),
        )
        auth._save_connection(record)

        with patch(
            "authsome.auth.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            assert auth.get_access_token("testoauth-valid-fallback") == "cached"

        stored = auth.get_connection("testoauth-valid-fallback")
        assert stored.status == ConnectionStatus.CONNECTED
        assert stored.access_token == "cached"

    def test_oauth_token_no_refresh_expired(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)

        now = utc_now()
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="old_acc",
            expires_at=now - timedelta(seconds=10),
        )
        auth._save_connection(record)

        with pytest.raises(TokenExpiredError):
            auth.get_access_token("testoauth")

    def test_get_access_token_valid_not_near_expiry(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)
        now = utc_now()
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="valid_token",
            expires_at=now + timedelta(seconds=1000),
        )
        auth._save_connection(record)
        assert auth.get_access_token("testoauth") == "valid_token"

    def test_oauth_token_missing_access_token(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
        )
        auth._save_connection(record)
        with pytest.raises(CredentialMissingError, match="No access token stored"):
            auth.get_access_token("testoauth")

    def test_refresh_token_no_oauth_config(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=None,
        )
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
        )
        with patch.object(auth, "get_provider", return_value=provider):
            with pytest.raises(RefreshFailedError, match="No OAuth config"):
                auth._refresh_token(record, "testoauth")

    def test_refresh_token_no_refresh_token(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            refresh_token=None,
        )
        with patch.object(auth, "get_provider", return_value=provider):
            with pytest.raises(RefreshFailedError, match="No refresh token available"):
                auth._refresh_token(record, "testoauth")


class TestAuthLayerLifecycle:
    """Connection lifecycle tests (logout, remove, revoke)."""

    def test_logout_nonexistent_is_noop(self, auth: AuthLayer) -> None:
        auth.logout("openai", "nonexistent")

    def test_logout_with_revocation(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(
                authorization_url="http://a",
                token_url="http://t",
                revocation_url="http://revoke",
            ),
        )
        auth.register_provider(provider)

        record = ConnectionRecord(
            schema_version=2,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="token123",
        )
        auth._save_connection(record)
        auth._update_provider_metadata("testoauth", "default")

        with patch("authsome.auth.http_client.post") as mock_post:
            auth.logout("testoauth")
            mock_post.assert_called_once_with("http://revoke", data={"token": "token123"}, timeout=15)

    def test_remove_connection(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-fixture-removeconnection-12"}))

        auth.remove("openai")
        with pytest.raises(ConnectionNotFoundError):
            auth.get_connection("openai")

    def test_remove_nonexistent(self, auth: AuthLayer) -> None:
        auth.remove("openai")

    def test_revoke_connection(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-fixture-revokeconnection-12"}))

        auth.revoke("openai")
        with pytest.raises(ConnectionNotFoundError):
            auth.get_connection("openai")


class TestAuthLayerExport:
    """Export operations tests."""

    def test_export_env_format(self, auth: AuthLayer, monkeypatch: pytest.MonkeyPatch) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-export-padded-for-regex"}))

        output = auth.export("openai", format=ExportFormat.ENV)
        assert output == "OPENAI_API_KEY=sk-export-padded-for-regex"

    def test_export_json_format(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-json-padded-for-regex"}))

        output = auth.export("openai", format=ExportFormat.JSON)
        data = json.loads(output)
        assert data["OPENAI_API_KEY"] == "sk-json-padded-for-regex"

    def test_export_all_connected_accounts(self, auth: AuthLayer) -> None:
        custom = ProviderDefinition(
            name="custom",
            display_name="Custom",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(),
            export=ExportConfig(env={"api_key": "CUSTOM_API_KEY"}),
        )
        auth.register_provider(custom)

        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-openai-padded-for-regex"}))
        auth.login("custom", input_provider=MockInputProvider({"api_key": "sk-custom"}))

        output = auth.export(format=ExportFormat.JSON)
        data = json.loads(output)

        assert data["CUSTOM_API_KEY"] == "sk-custom"
        assert data["OPENAI_API_KEY"] == "sk-openai-padded-for-regex"

    def test_export_oauth_format(self, auth: AuthLayer, monkeypatch: pytest.MonkeyPatch) -> None:
        provider = ProviderDefinition(
            name="testexport",
            display_name="Test Export",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        auth.register_provider(provider)

        record = ConnectionRecord(
            schema_version=2,
            provider="testexport",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token="acc",
            refresh_token="ref",
        )
        auth._save_connection(record)

        env_out = auth.export("testexport", format=ExportFormat.ENV)
        assert "TESTEXPORT_ACCESS_TOKEN=acc" in env_out
        assert "TESTEXPORT_REFRESH_TOKEN=ref" in env_out

    def test_export_shell_string(self, auth: AuthLayer) -> None:
        provider = ProviderDefinition(
            name="testexport-shell",
            display_name="Test Export Shell",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "Authorization"},
        )
        auth.register_provider(provider)
        auth._save_connection(
            ConnectionRecord(
                schema_version=2,
                provider="testexport-shell",
                profile="default",
                connection_name="default",
                auth_type=AuthType.API_KEY,
                status=ConnectionStatus.CONNECTED,
                api_key="key123",
            )
        )

        shell_out = auth.export("testexport-shell", format=ExportFormat.SHELL)
        assert shell_out == "export TESTEXPORT_SHELL_API_KEY=key123"


class TestAuthLayerDoctor:
    """Doctor health check tests."""

    def test_doctor_healthy(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        actx = AuthsomeContext.create(home=home)
        results = actx.doctor()
        assert results["home_exists"] is True
        assert results["encryption"] is True
        assert results["store"] is True
        assert results["issues"] == []
        actx.close()

    def test_doctor_vault_failure(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        actx = AuthsomeContext.create(home=home)
        with patch.object(actx.vault, "put", side_effect=Exception("vault boom")):
            res = actx.doctor()
            assert not res["encryption"]
            assert not res["store"]
            assert any("Vault" in issue for issue in res["issues"])
        actx.close()


class TestAuthLayerConnections:
    """Connection management tests."""

    def test_list_connections_empty(self, auth: AuthLayer) -> None:
        connections = auth.list_connections()
        assert connections == []

    def test_list_connections_after_login(self, auth: AuthLayer) -> None:
        auth.login("openai", input_provider=MockInputProvider({"api_key": "sk-fixture-listconnection-1234"}))

        connections = auth.list_connections()
        assert len(connections) == 1
        assert connections[0]["name"] == "openai"

    def test_get_nonexistent_connection(self, auth: AuthLayer) -> None:
        with pytest.raises(ConnectionNotFoundError):
            auth.get_connection("openai", connection="nonexistent")

    def test_v1_data_raises_helpful_error(self, auth: AuthLayer) -> None:
        from authsome.utils import build_store_key

        key = build_store_key(profile="default", provider="github", record_type="connection", connection="default")
        v1_record = json.dumps(
            {
                "schema_version": 1,
                "provider": "github",
                "profile": "default",
                "connection_name": "default",
                "auth_type": "oauth2",
                "status": "connected",
            }
        )
        auth._vault.put(key, v1_record, profile="default")

        with pytest.raises(AuthsomeError, match="v1 format"):
            auth.get_connection("github")
