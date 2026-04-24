"""Tests for the Authsome CLI."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from authsome.cli import cli
from authsome.errors import AuthsomeError, ProviderNotFoundError, StoreUnavailableError


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_client():
    with patch("authsome.cli.AuthClient") as mock:
        client = MagicMock()
        mock.return_value = client
        yield client


def test_init_command(runner, mock_client):
    mock_client.home = "/mock/home"
    result = runner.invoke(cli, ["init"])
    assert result.exit_code == 0
    assert "Initialized authsome at /mock/home" in result.output
    mock_client.init.assert_called_once()


def test_init_json(runner, mock_client):
    mock_client.home = "/mock/home"
    result = runner.invoke(cli, ["init", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "initialized"


def test_list_command(runner, mock_client):
    mock_client.list_connections.return_value = [
        {
            "name": "openai",
            "connections": [
                {
                    "connection_name": "default",
                    "status": "connected",
                    "auth_type": "api_key",
                    "scopes": ["read"],
                    "expires_at": "2030",
                }
            ],
        }
    ]

    mock_provider = MagicMock()
    mock_provider.name = "openai"
    mock_provider.display_name = "OpenAI"
    mock_provider.auth_type.value = "api_key"
    mock_client.list_providers_by_source.return_value = {
        "bundled": [mock_provider],
        "custom": [],
    }

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "Bundled Providers:" in result.output
    assert "OpenAI" in result.output
    assert "connected" in result.output


def test_list_command_no_connections_and_missing_scopes(runner, mock_client):
    mock_client.list_connections.return_value = [
        {
            "name": "openai",
            "connections": [
                {
                    "connection_name": "default",
                    "status": "connected",
                    "auth_type": "api_key",
                }
            ],
        }
    ]

    mock_provider = MagicMock()
    mock_provider.name = "openai"
    mock_provider.display_name = "OpenAI"
    mock_provider.auth_type.value = "api_key"

    mock_provider_empty = MagicMock()
    mock_provider_empty.name = "github"
    mock_provider_empty.display_name = "GitHub"
    mock_provider_empty.auth_type.value = "oauth2"

    mock_client.list_providers_by_source.return_value = {
        "bundled": [mock_provider, mock_provider_empty],
        "custom": [],
    }

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "(no connections)" in result.output


def test_list_json(runner, mock_client):
    mock_client.list_connections.return_value = []
    mock_client.list_providers_by_source.return_value = {"bundled": [], "custom": []}
    result = runner.invoke(cli, ["list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "bundled" in data


def test_login_command(runner, mock_client):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_client.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "openai"])
    assert result.exit_code == 0
    assert "Successfully logged in to openai" in result.output


def test_login_with_scopes_flag(runner, mock_client):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_client.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "github", "--scopes", "repo,user"])
    assert result.exit_code == 0

    # Assert scopes were split and passed to login
    mock_client.login.assert_called_with(
        provider="github",
        connection_name="default",
        scopes=["repo", "user"],
        flow_override=None,
        force=False,
    )


def test_login_json(runner, mock_client):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_client.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "openai", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "success"


def test_login_error(runner, mock_client):
    mock_client.login.side_effect = AuthsomeError("Already exists")
    result = runner.invoke(cli, ["login", "openai"])
    assert result.exit_code == 1
    assert "Error: Already exists" in result.output


def test_error_mapping(runner, mock_client):
    from authsome.errors import (
        AuthenticationFailedError,
        CredentialMissingError,
        RefreshFailedError,
    )

    mock_client.login.side_effect = ProviderNotFoundError("test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 3

    mock_client.login.side_effect = StoreUnavailableError("locked")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 7

    mock_client.login.side_effect = AuthenticationFailedError("fail")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 4

    mock_client.login.side_effect = CredentialMissingError("missing", provider="test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 5

    mock_client.login.side_effect = RefreshFailedError("refresh fail", provider="test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 6

    mock_client.login.side_effect = Exception("unknown")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 1


def test_logout(runner, mock_client):
    result = runner.invoke(cli, ["logout", "openai"])
    assert result.exit_code == 0
    mock_client.logout.assert_called_with("openai", "default")


def test_logout_json(runner, mock_client):
    result = runner.invoke(cli, ["logout", "openai", "--json"])
    assert result.exit_code == 0


def test_revoke(runner, mock_client):
    result = runner.invoke(cli, ["revoke", "openai"])
    assert result.exit_code == 0
    mock_client.revoke.assert_called_with("openai")


def test_revoke_json(runner, mock_client):
    result = runner.invoke(cli, ["revoke", "openai", "--json"])
    assert result.exit_code == 0


def test_remove(runner, mock_client):
    result = runner.invoke(cli, ["remove", "openai"])
    assert result.exit_code == 0
    mock_client.remove.assert_called_with("openai")


def test_remove_json(runner, mock_client):
    result = runner.invoke(cli, ["remove", "openai", "--json"])
    assert result.exit_code == 0


def test_get(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {
        "status": "connected",
        "access_token": "secret",
    }
    mock_client.crypto.decrypt.return_value = "decrypted_secret"
    mock_client.get_connection.return_value = mock_record

    result = runner.invoke(cli, ["get", "openai"])
    assert result.exit_code == 0
    assert "***REDACTED***" in result.output


def test_get_show_secret(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {
        "status": "connected",
        "access_token": "secret",
    }
    mock_record.access_token = "encrypted_secret"
    mock_client.crypto.decrypt.return_value = "decrypted_secret"
    mock_client.get_connection.return_value = mock_record

    result = runner.invoke(cli, ["get", "openai", "--show-secret"])
    assert result.exit_code == 0
    assert "decrypted_secret" in result.output


def test_get_field(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {"status": "connected"}
    mock_client.get_connection.return_value = mock_record

    result = runner.invoke(cli, ["get", "openai", "--field", "status"])
    assert result.exit_code == 0
    assert "connected" in result.output


def test_get_missing_field(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {"status": "connected"}
    mock_client.get_connection.return_value = mock_record

    result = runner.invoke(cli, ["get", "openai", "--field", "missing"])
    assert result.exit_code == 1


def test_get_json(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {"status": "connected"}
    mock_client.get_connection.return_value = mock_record
    result = runner.invoke(cli, ["get", "openai", "--json"])
    assert result.exit_code == 0


def test_get_field_json(runner, mock_client):
    mock_record = MagicMock()
    mock_record.model_dump.return_value = {"status": "connected"}
    mock_client.get_connection.return_value = mock_record
    result = runner.invoke(cli, ["get", "openai", "--json", "--field", "status"])
    assert result.exit_code == 0


def test_inspect(runner, mock_client):
    mock_def = MagicMock()
    mock_def.model_dump.return_value = {"name": "openai"}
    mock_client.get_provider.return_value = mock_def

    result = runner.invoke(cli, ["inspect", "openai"])
    assert result.exit_code == 0
    assert '"name": "openai"' in result.output


def test_inspect_json(runner, mock_client):
    mock_def = MagicMock()
    mock_def.model_dump.return_value = {"name": "openai"}
    mock_client.get_provider.return_value = mock_def

    result = runner.invoke(cli, ["inspect", "openai", "--json"])
    assert result.exit_code == 0


def test_export(runner, mock_client):
    mock_client.export.return_value = "export VAR=1"
    result = runner.invoke(cli, ["export", "openai", "--format", "shell"])
    assert result.exit_code == 0
    assert "export VAR=1" in result.output

    # test empty output
    mock_client.export.return_value = ""
    result2 = runner.invoke(cli, ["export", "openai", "--format", "shell"])
    assert result2.exit_code == 0
    assert result2.output == ""


def test_run(runner, mock_client):
    with patch("authsome.proxy.runner.ProxyRunner") as mock_runner_cls:
        mock_runner = MagicMock()
        mock_runner_cls.return_value = mock_runner
        mock_runner.run.return_value.returncode = 0

        result = runner.invoke(cli, ["run", "--", "echo", "hello"])
        assert result.exit_code == 0
        mock_runner.run.assert_called_with(["echo", "hello"])


def test_register_file_not_found(runner):
    result = runner.invoke(cli, ["register", "nonexistent.json"])
    assert result.exit_code == 1
    assert "File not found" in result.output


def test_register_success(runner, mock_client, tmp_path):
    f = tmp_path / "test.json"
    f.write_text(
        json.dumps(
            {
                "name": "test",
                "display_name": "Test",
                "auth_type": "api_key",
                "flow": "api_key",
                "api_key": {"header_name": "Auth"},
            }
        )
    )

    result = runner.invoke(cli, ["register", str(f)])
    assert result.exit_code == 0
    mock_client.register_provider.assert_called_once()


def test_register_success_json(runner, mock_client, tmp_path):
    f = tmp_path / "test.json"
    f.write_text(
        json.dumps(
            {
                "name": "test",
                "display_name": "Test",
                "auth_type": "api_key",
                "flow": "api_key",
                "api_key": {"header_name": "Auth"},
            }
        )
    )

    result = runner.invoke(cli, ["register", str(f), "--json"])
    assert result.exit_code == 0


def test_register_bad_json(runner, mock_client, tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{bad")
    result = runner.invoke(cli, ["register", str(f)])
    assert result.exit_code == 1


def test_whoami(runner, mock_client):
    mock_client.home = "/mock/home"
    mock_client.config.encryption.mode = "keyring"
    result = runner.invoke(cli, ["whoami"])
    assert result.exit_code == 0
    assert "/mock/home" in result.output


def test_whoami_no_encryption_config(runner, mock_client):
    mock_client.home = "/mock/home"
    mock_client.config.encryption = None
    result = runner.invoke(cli, ["whoami", "--json"])
    assert result.exit_code == 0


def test_doctor(runner, mock_client):
    mock_client.doctor.return_value = {
        "home_exists": True,
        "encryption": False,
        "issues": ["error"],
        "providers_count": 0,
    }
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_doctor_json(runner, mock_client):
    mock_client.doctor.return_value = {
        "home_exists": True,
        "encryption": True,
        "issues": [],
    }
    result = runner.invoke(cli, ["doctor", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["home_exists"] is True


def test_doctor_all_ok(runner, mock_client):
    mock_client.doctor.return_value = {
        "home_exists": True,
        "encryption": True,
        "issues": [],
        "providers_count": 1,
    }
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_common_options_error_handling_json(runner, mock_client):
    mock_client.login.side_effect = AuthsomeError("Error")
    result = runner.invoke(cli, ["login", "openai", "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["error"] == "AuthsomeError"


def test_echo_no_color(runner, mock_client):
    mock_client.logout.return_value = None
    result = runner.invoke(cli, ["logout", "openai", "--no-color"])
    assert result.exit_code == 0


def test_echo_quiet(runner, mock_client):
    mock_client.logout.return_value = None
    result = runner.invoke(cli, ["logout", "openai", "--quiet"])
    assert result.exit_code == 0
    assert "Logged out" not in result.output
