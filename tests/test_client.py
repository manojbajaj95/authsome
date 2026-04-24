"""Tests for the AuthClient core."""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from authsome.client import AuthClient
from authsome.errors import (
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    ProfileNotFoundError,
    ProviderNotFoundError,
    RefreshFailedError,
    TokenExpiredError,
    UnsupportedFlowError,
)
from authsome.models.connection import (
    ConnectionRecord,
    ProviderClientRecord,
)
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.provider import ApiKeyConfig, OAuthConfig, ProviderDefinition
from authsome.utils import utc_now


@pytest.fixture
def client(tmp_path: Path) -> AuthClient:
    home = tmp_path / ".authsome"
    with AuthClient(home=home) as c:
        c.init()
        yield c


class TestAuthClientInit:
    """Initialization and directory setup tests."""

    def test_init_creates_structure(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()

        assert (home / "version").exists()
        assert (home / "config.json").exists()
        assert (home / "providers").is_dir()
        assert (home / "profiles" / "default").is_dir()
        assert (home / "profiles" / "default" / "metadata.json").exists()

    def test_version_file_content(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()

        content = (home / "version").read_text()
        assert content.strip() == "1"

    def test_config_defaults(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()

        config_data = json.loads((home / "config.json").read_text())
        assert config_data["spec_version"] == 1
        assert config_data["default_profile"] == "default"

    def test_env_home_override(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        custom_home = tmp_path / "custom-authsome"
        monkeypatch.setenv("AUTHSOME_HOME", str(custom_home))
        client = AuthClient()
        assert client.home == custom_home

    def test_explicit_home_overrides_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AUTHSOME_HOME", "/some/other/path")
        explicit = tmp_path / "explicit"
        client = AuthClient(home=explicit)
        assert client.home == explicit

    def test_idempotent_init(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()
        client.init()  # Should not fail
        assert (home / "version").exists()

    def test_authclient_default_home(self, monkeypatch):
        monkeypatch.delenv("AUTHSOME_HOME", raising=False)
        with patch("authsome.client.Path.home", return_value=Path("/mock/home")):
            with AuthClient() as c:
                assert str(c.home) == "/mock/home/.authsome"

    def test_authclient_keyring_crypto(self, tmp_path, monkeypatch):
        home = tmp_path / ".authsome"
        home.mkdir()
        (home / "config.json").write_text('{"encryption": {"mode": "keyring"}}')
        with patch("authsome.client.KeyringCryptoBackend") as mock_backend:
            with AuthClient(home=home) as c:
                _ = c.crypto
                mock_backend.assert_called_once()

    def test_load_config_bad_json(self, tmp_path):
        home = tmp_path / ".authsome"
        home.mkdir()
        (home / "config.json").write_text("{bad")
        with AuthClient(home=home) as c:
            assert c.config.default_profile == "default"


class TestAuthClientProviders:
    """Provider operations tests."""

    def test_list_providers_includes_bundled(self, client: AuthClient) -> None:
        providers = client.list_providers()
        names = [p.name for p in providers]
        assert "openai" in names
        assert "github" in names

    def test_get_provider(self, client: AuthClient) -> None:
        provider = client.get_provider("openai")
        assert provider.name == "openai"
        assert provider.auth_type == AuthType.API_KEY

    def test_get_nonexistent_provider(self, client: AuthClient) -> None:
        with pytest.raises(ProviderNotFoundError):
            client.get_provider("nonexistent")

    def test_register_and_get_custom_provider(self, client: AuthClient) -> None:
        custom = ProviderDefinition(
            name="custom",
            display_name="Custom Provider",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(env_var="CUSTOM_KEY"),
        )
        client.register_provider(custom)
        loaded = client.get_provider("custom")
        assert loaded.display_name == "Custom Provider"

    def test_list_providers_by_source(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testlocal",
            display_name="Test Local",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "Authorization"},
        )
        client.register_provider(provider)
        sources = client.list_providers_by_source()
        assert "bundled" in sources
        assert "custom" in sources
        assert len(sources["custom"]) > 0


class TestAuthClientProfiles:
    """Profile management tests."""

    def test_default_profile_created(self, client: AuthClient) -> None:
        profiles = client.list_profiles()
        names = [p.name for p in profiles]
        assert "default" in names

    def test_create_profile(self, client: AuthClient) -> None:
        client.create_profile("work", description="Work profile")
        profiles = client.list_profiles()
        names = [p.name for p in profiles]
        assert "work" in names

    def test_set_default_profile(self, client: AuthClient) -> None:
        client.create_profile("work")
        client.set_default_profile("work")
        assert client.config.default_profile == "work"

    def test_set_nonexistent_default_profile(self, client: AuthClient) -> None:
        with pytest.raises(ProfileNotFoundError):
            client.set_default_profile("nonexistent")

    def test_list_profiles_issues(self, client: AuthClient):
        profiles_dir = client.home / "profiles"
        bad_dir = profiles_dir / "bad"
        bad_dir.mkdir()
        (bad_dir / "metadata.json").write_text("{bad json")

        profiles = client.list_profiles()
        names = [p.name for p in profiles]
        assert "default" in names
        assert "bad" not in names

    def test_list_profiles_no_dir(self, client: AuthClient):
        import shutil

        profiles_dir = client.home / "profiles"
        shutil.rmtree(profiles_dir)
        assert client.list_profiles() == []


class TestAuthClientLogin:
    """Authentication flow integration tests."""

    def test_api_key_login_and_get(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-test-123"},
        ):
            record = client.login("openai")

        assert record.status == ConnectionStatus.CONNECTED
        assert record.auth_type == AuthType.API_KEY

        conn = client.get_connection("openai")
        assert conn.status == ConnectionStatus.CONNECTED

    def test_login_connection_exists(self, client: AuthClient):
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-1"},
        ):
            client.login("openai", "default")

        with pytest.raises(AuthsomeError, match="already exists"):
            client.login("openai", "default", force=False)

        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-2"},
        ):
            client.login("openai", "default", force=True)

    def test_login_unsupported_flow(self, client: AuthClient):
        def mock_get_provider(name):
            mock_def = MagicMock()
            mock_def.flow = MagicMock(value="invalid_flow")
            return mock_def

        with patch.object(client, "get_provider", mock_get_provider):
            with pytest.raises(UnsupportedFlowError):
                client.login("test")

    def test_login_oauth_bridge_prompt(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        client.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("access"),
        )

        with patch("authsome.client._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = mock_record
            handlers.get.return_value = lambda: mock_handler

            with patch(
                "authsome.flows.bridge.secure_input_bridge",
                return_value={"client_id": "cid", "client_secret": "csec"},
            ) as mock_bridge:
                client.login("testoauth")
                mock_bridge.assert_called_once()

                creds = client.get_provider_client_credentials("testoauth", "default")
                assert creds.client_id == "cid"
                assert client.crypto.decrypt(creds.client_secret) == "csec"

    def test_login_dcr_metadata_extraction(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testdcr",
            display_name="Test DCR",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        client.register_provider(provider)

        encrypted_secret = client.crypto.encrypt("csec")
        mock_record = ConnectionRecord(
            schema_version=1,
            provider="testdcr",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("access"),
            metadata={
                "_dcr_client_id": "cid",
                "_dcr_client_secret": encrypted_secret.model_dump(),
            },
        )

        with patch("authsome.client._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = mock_record
            handlers.get.return_value = lambda: mock_handler

            client.login("testdcr", scopes=["test_scope"])

            creds = client.get_provider_client_credentials("testdcr", "default")
            assert creds.client_id == "cid"
            assert client.crypto.decrypt(creds.client_secret) == "csec"

    def test_login_dcr_metadata_extraction_no_secret(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testdcr2",
            display_name="Test DCR 2",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(authorization_url="http://auth", token_url="http://token"),
        )
        client.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=1,
            provider="testdcr2",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("access"),
            metadata={"_dcr_client_id": "cid"},
        )

        with patch("authsome.client._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = mock_record
            handlers.get.return_value = lambda: mock_handler

            client.login("testdcr2", scopes=["test_scope"])

            creds = client.get_provider_client_credentials("testdcr2", "default")
            assert creds.client_id == "cid"
            assert creds.client_secret is None

    def test_login_oauth_scopes_prompt(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth_scopes",
            display_name="Test OAuth Scopes",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(
                authorization_url="http://auth",
                token_url="http://token",
                scopes=["read", "write"],
            ),
        )
        client.register_provider(provider)

        mock_record = ConnectionRecord(
            schema_version=1,
            provider="testoauth_scopes",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("access"),
        )

        with patch("authsome.client._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = mock_record
            handlers.get.return_value = lambda: mock_handler

            with patch(
                "authsome.flows.bridge.secure_input_bridge",
                return_value={"client_id": "cid", "scopes": "read,write,admin"},
            ) as mock_bridge:
                client.login("testoauth_scopes")
                mock_bridge.assert_called_once()
                fields = mock_bridge.call_args[0][1]
                scopes_field = next(f for f in fields if f.get("name") == "scopes")
                assert scopes_field["value"] == "read,write"

                creds = client.get_provider_client_credentials("testoauth_scopes", "default")
                assert creds.scopes == ["read", "write", "admin"]

                # Check authenticate call
                mock_handler.authenticate.assert_called_once()
                call_args = mock_handler.authenticate.call_args[1]
                assert call_args["scopes"] == ["read", "write", "admin"]

    def test_login_oauth_scopes_override(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth_scopes_over",
            display_name="Test OAuth Scopes Over",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(
                authorization_url="http://auth",
                token_url="http://token",
                scopes=["read", "write"],
            ),
        )
        client.register_provider(provider)

        client._save_provider_client_credentials(
            ProviderClientRecord(
                profile="default",
                provider="testoauth_scopes_over",
                client_id="cid",
                scopes=["read"],
            )
        )

        mock_record = ConnectionRecord(
            schema_version=1,
            provider="testoauth_scopes_over",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("access"),
        )

        with patch("authsome.client._FLOW_HANDLERS") as handlers:
            mock_handler = MagicMock()
            mock_handler.authenticate.return_value = mock_record
            handlers.get.return_value = lambda: mock_handler

            client.login("testoauth_scopes_over", scopes=["custom"])

            # Should NOT prompt because scopes are overridden and client_id exists
            mock_handler.authenticate.assert_called_once()
            call_args = mock_handler.authenticate.call_args[1]
            assert call_args["scopes"] == ["custom"]

            # Verify persisted scopes were NOT changed
            creds = client.get_provider_client_credentials("testoauth_scopes_over", "default")
            assert creds.scopes == ["read"]


class TestAuthClientCredentials:
    """Credential retrieval tests."""

    def test_api_key_get_access_token(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-test-456"},
        ):
            client.login("openai")

        token = client.get_access_token("openai")
        assert token == "sk-test-456"

    def test_api_key_get_auth_headers(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-test-789"},
        ):
            client.login("openai")

        headers = client.get_auth_headers("openai")
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer sk-test-789"

    def test_get_access_token_oauth(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)

        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("token123"),
        )
        client._save_connection(record)

        assert client.get_access_token("testoauth") == "token123"

    def test_get_access_token_unsupported(self, client: AuthClient):
        mock_record = MagicMock()
        mock_record.auth_type = "UNKNOWN"

        with patch.object(client, "get_connection", return_value=mock_record):
            with pytest.raises(CredentialMissingError, match="Unsupported auth type"):
                client.get_access_token("test")

    def test_get_auth_headers_unsupported(self, client: AuthClient):
        mock_record = MagicMock()
        mock_record.auth_type = "UNKNOWN"

        with patch.object(client, "get_provider"):
            with patch.object(client, "get_connection", return_value=mock_record):
                with pytest.raises(CredentialMissingError, match="Cannot build headers"):
                    client.get_auth_headers("test")

    def test_get_auth_headers_api_key_custom(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "X-API-KEY", "header_prefix": ""},
        )
        client.register_provider(provider)
        record = ConnectionRecord(
            schema_version=1,
            provider="testapi",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key=client.crypto.encrypt("key123"),
        )
        client._save_connection(record)

        headers = client.get_auth_headers("testapi")
        assert headers["X-API-KEY"] == "key123"

    def test_get_auth_headers_oauth(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("oauth123"),
        )
        client._save_connection(record)

        headers = client.get_auth_headers("testoauth")
        assert headers["Authorization"] == "Bearer oauth123"

    def test_get_auth_headers_api_key_no_config(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testapi",
            display_name="Test API",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
        )
        record = ConnectionRecord(
            schema_version=1,
            provider="testapi",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key=client.crypto.encrypt("key123"),
        )
        client._save_connection(record)

        with patch.object(client, "get_provider", return_value=provider):
            headers = client.get_auth_headers("testapi")
            assert headers["Authorization"] == "Bearer key123"

    def test_get_api_key_missing(self, client: AuthClient):
        provider = ProviderDefinition(
            name="test",
            display_name="Test",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key={"header_name": "Authorization"},
        )
        client.register_provider(provider)
        record = ConnectionRecord(
            schema_version=1,
            provider="test",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
        )
        client._save_connection(record)
        with pytest.raises(CredentialMissingError, match="No API key stored"):
            client._get_api_key(record)


class TestAuthClientTokenRefresh:
    """OAuth token refresh logic tests."""

    def test_oauth_token_refresh(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)

        now = utc_now()
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("old_acc"),
            refresh_token=client.crypto.encrypt("ref"),
            expires_at=now - timedelta(seconds=10),  # expired
        )
        client._save_connection(record)

        with pytest.raises(RefreshFailedError, match="No client_id"):
            client.get_access_token("testoauth")

        client._save_provider_client_credentials(
            ProviderClientRecord(
                profile="default",
                provider="testoauth",
                client_id="cid",
                client_secret=client.crypto.encrypt("sec"),
            )
        )

        mock_token_resp = MagicMock()
        mock_token_resp.json.return_value = {
            "access_token": "new_acc",
            "refresh_token": "new_ref",
            "expires_in": 3600,
        }

        with patch("authsome.client.http_client.post", return_value=mock_token_resp):
            assert client.get_access_token("testoauth") == "new_acc"

        record.expires_at = now - timedelta(seconds=10)
        client._save_connection(record)
        with patch(
            "authsome.client.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            with pytest.raises(RefreshFailedError):
                client.get_access_token("testoauth")

    def test_oauth_token_no_refresh_expired(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)

        now = utc_now()
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("old_acc"),
            expires_at=now - timedelta(seconds=10),
        )
        client._save_connection(record)

        with pytest.raises(TokenExpiredError):
            client.get_access_token("testoauth")

    def test_oauth_token_refresh_failed_but_still_valid(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)

        now = utc_now()
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("valid_acc"),
            refresh_token=client.crypto.encrypt("ref"),
            expires_at=now + timedelta(seconds=100),
        )
        client._save_connection(record)

        client._save_provider_client_credentials(
            ProviderClientRecord(profile="default", provider="testoauth", client_id="cid")
        )

        with patch(
            "authsome.client.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            assert client.get_access_token("testoauth") == "valid_acc"

    def test_oauth_token_missing_access_token(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
        )
        client._save_connection(record)
        with pytest.raises(CredentialMissingError, match="No access token stored"):
            client.get_access_token("testoauth")

    def test_get_access_token_valid_not_near_expiry(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)
        now = utc_now()
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("valid_token"),
            expires_at=now + timedelta(seconds=1000),
        )
        client._save_connection(record)
        assert client.get_access_token("testoauth") == "valid_token"

    def test_get_access_token_valid_no_refresh(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)
        now = utc_now()
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("valid_token_no_ref"),
            expires_at=now + timedelta(seconds=100),
        )
        client._save_connection(record)
        assert client.get_access_token("testoauth") == "valid_token_no_ref"

    def test_refresh_token_no_oauth_config(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=None,
        )
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
        )
        with patch.object(client, "get_provider", return_value=provider):
            with pytest.raises(RefreshFailedError, match="No OAuth config"):
                client._refresh_token(record, "testoauth")

    def test_refresh_token_no_refresh_token(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testoauth",
            display_name="Test OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            refresh_token=None,
        )
        with patch.object(client, "get_provider", return_value=provider):
            with pytest.raises(RefreshFailedError, match="No refresh token available"):
                client._refresh_token(record, "testoauth")


class TestAuthClientLifecycle:
    """Connection lifecycle tests (logout, remove, revoke)."""

    def test_logout_errors_and_revocation(self, client: AuthClient):
        client.logout("openai", "nonexistent")

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
        client.register_provider(provider)

        record = ConnectionRecord(
            schema_version=1,
            provider="testoauth",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("token123"),
        )
        client._save_connection(record)
        client._update_provider_metadata("default", "testoauth", "default")

        with patch("authsome.client.http_client.post") as mock_post:
            client.logout("testoauth")
            mock_post.assert_called_once_with("http://revoke", data={"token": "token123"}, timeout=15)

        client._save_connection(record)
        with patch(
            "authsome.client.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            client.logout("testoauth")

    def test_remove_connection(self, client: AuthClient) -> None:
        with patch("authsome.flows.bridge.secure_input_bridge", return_value={"api_key": "key"}):
            client.login("openai")

        client.remove("openai")
        with pytest.raises(ConnectionNotFoundError):
            client.get_connection("openai")

    def test_remove_nonexistent(self, client: AuthClient) -> None:
        client.remove("openai")

    def test_revoke_connection(self, client: AuthClient) -> None:
        with patch("authsome.flows.bridge.secure_input_bridge", return_value={"api_key": "key"}):
            client.login("openai")

        client.revoke("openai")
        with pytest.raises(ConnectionNotFoundError):
            client.get_connection("openai")

    def test_remove_bundled_provider(self, client: AuthClient):
        client.remove("openai")
        assert not (client.home / "providers" / "openai.json").exists()


class TestAuthClientExport:
    """Export operations tests."""

    def test_export_env_format(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-export"},
        ):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.ENV)
        assert "OPENAI_API_KEY=sk-export" in output

    def test_export_shell_format(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-shell"},
        ):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.SHELL)
        assert "export OPENAI_API_KEY=sk-shell" in output

    def test_export_json_format(self, client: AuthClient) -> None:
        with patch(
            "authsome.flows.bridge.secure_input_bridge",
            return_value={"api_key": "sk-json"},
        ):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.JSON)
        data = json.loads(output)
        assert data["OPENAI_API_KEY"] == "sk-json"

    def test_export_oauth_and_unknown(self, client: AuthClient):
        provider = ProviderDefinition(
            name="testexport",
            display_name="Test Export",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.PKCE,
            oauth=OAuthConfig(authorization_url="http://a", token_url="http://t"),
        )
        client.register_provider(provider)

        record = ConnectionRecord(
            schema_version=1,
            provider="testexport",
            profile="default",
            connection_name="default",
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            access_token=client.crypto.encrypt("acc"),
            refresh_token=client.crypto.encrypt("ref"),
        )
        client._save_connection(record)

        env_out = client.export("testexport", format=ExportFormat.ENV)
        assert "TESTEXPORT_ACCESS_TOKEN=acc" in env_out
        assert "TESTEXPORT_REFRESH_TOKEN=ref" in env_out
        assert client.export("testexport", format=MagicMock()) == ""


class TestAuthClientDoctor:
    """Doctor health check tests."""

    def test_doctor_healthy(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()

        results = client.doctor()
        assert results["home_exists"] is True
        assert results["issues"] == []

    def test_doctor_issues(self, client: AuthClient, monkeypatch):
        with patch.object(client.crypto, "encrypt", side_effect=Exception("crypto boom")):
            res = client.doctor()
            assert not res["encryption"]
            assert "Encryption: crypto boom" in res["issues"]

        store = client._get_store("default")
        with patch.object(store, "set", side_effect=Exception("store boom")):
            res = client.doctor()
            assert not res["store"]
            assert "Store: store boom" in res["issues"]

        with patch.object(client, "list_providers", side_effect=Exception("prov boom")):
            res = client.doctor()
            assert "Providers: prov boom" in res["issues"]

        with patch.object(client, "list_profiles", side_effect=Exception("prof boom")):
            res = client.doctor()
            assert "Profiles: prof boom" in res["issues"]


class TestAuthClientConnections:
    """Connection management tests."""

    def test_list_connections_empty(self, client: AuthClient) -> None:
        connections = client.list_connections()
        assert connections == []

    def test_list_connections_after_login(self, client: AuthClient) -> None:
        with patch("authsome.flows.bridge.secure_input_bridge", return_value={"api_key": "key"}):
            client.login("openai")

        connections = client.list_connections()
        assert len(connections) == 1
        assert connections[0]["name"] == "openai"

    def test_list_connections_edge_cases(self, client: AuthClient):
        store = client._get_store("default")
        store.set("profile:default:openai:junk:default", '{"junk": true}')
        store.set("profile:default:openai:connection", '{"junk": true}')
        store.set("profile:default:openai:connection:test", "")

        connections = client.list_connections()
        assert connections == []

    def test_get_nonexistent_connection(self, client: AuthClient) -> None:
        with pytest.raises(ConnectionNotFoundError):
            client.get_connection("openai", connection="nonexistent")

    def test_get_store_missing_profile(self, client: AuthClient):
        with pytest.raises(ProfileNotFoundError):
            client._get_store("missing")

    def test_metadata_cleanup(self, client: AuthClient):
        client._update_provider_metadata("default", "openai", "conn1")
        client._update_provider_metadata("default", "openai", "conn2")

        client._remove_from_provider_metadata("default", "openai", "conn1")
        store = client._get_store("default")
        meta = store.get("profile:default:openai:metadata")
        assert "conn1" not in meta
        assert "conn2" in meta

        client._remove_from_provider_metadata("default", "openai", "conn2")
        meta = json.loads(store.get("profile:default:openai:metadata"))
        assert meta["last_used_connection"] is None
