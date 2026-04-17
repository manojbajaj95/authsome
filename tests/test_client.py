"""Tests for the AuthClient core."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from authsome.client import AuthClient
from authsome.errors import (
    ConnectionNotFoundError,
    ProfileNotFoundError,
    ProviderNotFoundError,
)
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.provider import ApiKeyConfig, ProviderDefinition


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


class TestAuthClientProviders:
    """Provider operations tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

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
            flow=FlowType.API_KEY_PROMPT,
            api_key=ApiKeyConfig(env_var="CUSTOM_KEY"),
        )
        client.register_provider(custom)
        loaded = client.get_provider("custom")
        assert loaded.display_name == "Custom Provider"


class TestAuthClientProfiles:
    """Profile management tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

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


class TestAuthClientApiKeyLogin:
    """API key login integration tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

    def test_api_key_login_and_get(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-test-123"):
            record = client.login("openai")

        assert record.status == ConnectionStatus.CONNECTED
        assert record.auth_type == AuthType.API_KEY

        # Get connection
        conn = client.get_connection("openai")
        assert conn.status == ConnectionStatus.CONNECTED

    def test_api_key_get_access_token(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-test-456"):
            client.login("openai")

        token = client.get_access_token("openai")
        assert token == "sk-test-456"

    def test_api_key_get_auth_headers(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-test-789"):
            client.login("openai")

        headers = client.get_auth_headers("openai")
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer sk-test-789"

    def test_api_key_multiple_connections(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="key-1"):
            client.login("openai", connection_name="personal")

        with patch("authsome.flows.api_key.getpass.getpass", return_value="key-2"):
            client.login("openai", connection_name="work")

        assert client.get_access_token("openai", connection="personal") == "key-1"
        assert client.get_access_token("openai", connection="work") == "key-2"

    def test_get_nonexistent_connection(self, client: AuthClient) -> None:
        with pytest.raises(ConnectionNotFoundError):
            client.get_connection("openai", connection="nonexistent")


class TestAuthClientExport:
    """Export operations tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

    def test_export_env_format(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-export"):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.ENV)
        assert "OPENAI_API_KEY=sk-export" in output

    def test_export_shell_format(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-shell"):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.SHELL)
        assert "export OPENAI_API_KEY=sk-shell" in output

    def test_export_json_format(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="sk-json"):
            client.login("openai")

        output = client.export("openai", format=ExportFormat.JSON)
        data = json.loads(output)
        assert data["OPENAI_API_KEY"] == "sk-json"


class TestAuthClientRemoveRevoke:
    """Remove and revoke operations tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

    def test_remove_connection(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="key"):
            client.login("openai")

        client.remove("openai")

        with pytest.raises(ConnectionNotFoundError):
            client.get_connection("openai")

    def test_remove_nonexistent(self, client: AuthClient) -> None:
        with pytest.raises(ConnectionNotFoundError):
            client.remove("openai")

    def test_revoke_connection(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="key"):
            client.login("openai")

        client.revoke("openai")

        conn = client.get_connection("openai")
        assert conn.status == ConnectionStatus.REVOKED
        assert conn.api_key is None


class TestAuthClientDoctor:
    """Doctor health check tests."""

    def test_doctor_healthy(self, tmp_path: Path) -> None:
        home = tmp_path / ".authsome"
        client = AuthClient(home=home)
        client.init()

        results = client.doctor()
        assert results["home_exists"] is True
        assert results["version_file"] is True
        assert results["config_file"] is True
        assert results["encryption"] is True
        assert results["store"] is True
        assert results["providers_count"] > 0
        assert results["profiles_count"] > 0
        assert results["issues"] == []


class TestAuthClientListConnections:
    """List connections tests."""

    @pytest.fixture
    def client(self, tmp_path: Path) -> AuthClient:
        home = tmp_path / ".authsome"
        c = AuthClient(home=home)
        c.init()
        return c

    def test_list_connections_empty(self, client: AuthClient) -> None:
        connections = client.list_connections()
        assert connections == []

    def test_list_connections_after_login(self, client: AuthClient) -> None:
        with patch("authsome.flows.api_key.getpass.getpass", return_value="key"):
            client.login("openai")

        connections = client.list_connections()
        assert len(connections) == 1
        assert connections[0]["name"] == "openai"
        assert len(connections[0]["connections"]) == 1
        assert connections[0]["connections"][0]["status"] == "connected"
