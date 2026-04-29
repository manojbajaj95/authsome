"""Tests for the Authsome CLI."""

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from authsome.auth.models.enums import ExportFormat
from authsome.cli import cli
from authsome.errors import AuthsomeError, ProviderNotFoundError, StoreUnavailableError


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def mock_ctx(tmp_path):
    """Patch AuthsomeContext.create and return the mock context."""
    with patch("authsome.cli.AuthsomeContext") as mock_cls, patch("authsome.cli.audit"):
        ctx = MagicMock()
        ctx.home = tmp_path
        mock_cls.create.return_value = ctx
        yield ctx


def test_list_command(runner, mock_ctx):
    mock_ctx.auth.list_connections.return_value = [
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
    mock_ctx.auth.list_providers_by_source.return_value = {
        "bundled": [mock_provider],
        "custom": [],
    }

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "Bundled Providers:" in result.output
    assert "OpenAI" in result.output
    assert "connected" in result.output


def test_list_command_no_connections(runner, mock_ctx):
    mock_ctx.auth.list_connections.return_value = []

    mock_provider = MagicMock()
    mock_provider.name = "openai"
    mock_provider.display_name = "OpenAI"
    mock_provider.auth_type.value = "api_key"

    mock_provider_empty = MagicMock()
    mock_provider_empty.name = "github"
    mock_provider_empty.display_name = "GitHub"
    mock_provider_empty.auth_type.value = "oauth2"

    mock_ctx.auth.list_providers_by_source.return_value = {
        "bundled": [mock_provider, mock_provider_empty],
        "custom": [],
    }

    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "(no connections)" in result.output


def test_list_json(runner, mock_ctx):
    mock_ctx.auth.list_connections.return_value = []
    mock_ctx.auth.list_providers_by_source.return_value = {"bundled": [], "custom": []}
    result = runner.invoke(cli, ["list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "bundled" in data


def test_login_command(runner, mock_ctx):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_ctx.auth.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "openai"])
    assert result.exit_code == 0
    assert "Successfully logged in to openai" in result.output


def test_login_with_scopes_flag(runner, mock_ctx):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_ctx.auth.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "github", "--scopes", "repo,user"])
    assert result.exit_code == 0

    mock_ctx.auth.login.assert_called_with(
        provider="github",
        connection_name="default",
        scopes=["repo", "user"],
        flow_override=None,
        force=False,
        base_url=None,
    )


def test_login_json(runner, mock_ctx):
    mock_record = MagicMock()
    mock_record.status.value = "connected"
    mock_ctx.auth.login.return_value = mock_record

    result = runner.invoke(cli, ["login", "openai", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "success"


def test_login_error(runner, mock_ctx):
    mock_ctx.auth.login.side_effect = AuthsomeError("Already exists")
    result = runner.invoke(cli, ["login", "openai"])
    assert result.exit_code == 1
    assert "Error: Already exists" in result.output


def test_error_mapping(runner, mock_ctx):
    from authsome.errors import (
        AuthenticationFailedError,
        CredentialMissingError,
        RefreshFailedError,
    )

    mock_ctx.auth.login.side_effect = ProviderNotFoundError("test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 3

    mock_ctx.auth.login.side_effect = StoreUnavailableError("locked")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 7

    mock_ctx.auth.login.side_effect = AuthenticationFailedError("fail")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 4

    mock_ctx.auth.login.side_effect = CredentialMissingError("missing", provider="test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 5

    mock_ctx.auth.login.side_effect = RefreshFailedError("refresh fail", provider="test")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 6

    mock_ctx.auth.login.side_effect = Exception("unknown")
    result = runner.invoke(cli, ["login", "test"])
    assert result.exit_code == 1


def test_logout(runner, mock_ctx):
    result = runner.invoke(cli, ["logout", "openai"])
    assert result.exit_code == 0
    mock_ctx.auth.logout.assert_called_with("openai", "default")


def test_logout_json(runner, mock_ctx):
    result = runner.invoke(cli, ["logout", "openai", "--json"])
    assert result.exit_code == 0


def test_revoke(runner, mock_ctx):
    result = runner.invoke(cli, ["revoke", "openai"])
    assert result.exit_code == 0
    mock_ctx.auth.revoke.assert_called_with("openai")


def test_revoke_json(runner, mock_ctx):
    result = runner.invoke(cli, ["revoke", "openai", "--json"])
    assert result.exit_code == 0


def test_remove(runner, mock_ctx):
    result = runner.invoke(cli, ["remove", "openai"])
    assert result.exit_code == 0
    mock_ctx.auth.remove.assert_called_with("openai")


def test_remove_json(runner, mock_ctx):
    result = runner.invoke(cli, ["remove", "openai", "--json"])
    assert result.exit_code == 0


def test_get(runner, mock_ctx):
    from authsome.auth.models.connection import ConnectionRecord
    from authsome.auth.models.enums import AuthType, ConnectionStatus

    record = ConnectionRecord(
        provider="openai",
        profile="default",
        connection_name="default",
        auth_type=AuthType.API_KEY,
        status=ConnectionStatus.CONNECTED,
        api_key="sk-super-secret",
    )
    mock_ctx.auth.get_connection.return_value = record

    result = runner.invoke(cli, ["get", "openai"])
    assert result.exit_code == 0
    assert "***REDACTED***" in result.output
    assert "sk-super-secret" not in result.output


def test_get_show_secret(runner, mock_ctx):
    from authsome.auth.models.connection import ConnectionRecord
    from authsome.auth.models.enums import AuthType, ConnectionStatus

    record = ConnectionRecord(
        provider="openai",
        profile="default",
        connection_name="default",
        auth_type=AuthType.API_KEY,
        status=ConnectionStatus.CONNECTED,
        api_key="sk-super-secret",
    )
    mock_ctx.auth.get_connection.return_value = record

    result = runner.invoke(cli, ["get", "openai", "--show-secret"])
    assert result.exit_code == 0
    assert "sk-super-secret" in result.output


def test_get_field(runner, mock_ctx):
    from authsome.auth.models.connection import ConnectionRecord
    from authsome.auth.models.enums import AuthType, ConnectionStatus

    record = ConnectionRecord(
        provider="openai",
        profile="default",
        connection_name="default",
        auth_type=AuthType.API_KEY,
        status=ConnectionStatus.CONNECTED,
    )
    mock_ctx.auth.get_connection.return_value = record

    result = runner.invoke(cli, ["get", "openai", "--field", "status"])
    assert result.exit_code == 0
    assert "connected" in result.output


def test_get_missing_field(runner, mock_ctx):
    from authsome.auth.models.connection import ConnectionRecord
    from authsome.auth.models.enums import AuthType, ConnectionStatus

    record = ConnectionRecord(
        provider="openai",
        profile="default",
        connection_name="default",
        auth_type=AuthType.API_KEY,
        status=ConnectionStatus.CONNECTED,
    )
    mock_ctx.auth.get_connection.return_value = record

    result = runner.invoke(cli, ["get", "openai", "--field", "missing"])
    assert result.exit_code == 1


def test_get_json(runner, mock_ctx):
    from authsome.auth.models.connection import ConnectionRecord
    from authsome.auth.models.enums import AuthType, ConnectionStatus

    record = ConnectionRecord(
        provider="openai",
        profile="default",
        connection_name="default",
        auth_type=AuthType.API_KEY,
        status=ConnectionStatus.CONNECTED,
    )
    mock_ctx.auth.get_connection.return_value = record
    result = runner.invoke(cli, ["get", "openai", "--json"])
    assert result.exit_code == 0


def test_inspect(runner, mock_ctx):
    mock_def = MagicMock()
    mock_def.model_dump.return_value = {"name": "openai"}
    mock_ctx.auth.get_provider.return_value = mock_def

    result = runner.invoke(cli, ["inspect", "openai"])
    assert result.exit_code == 0
    assert '"name": "openai"' in result.output


def test_inspect_json(runner, mock_ctx):
    mock_def = MagicMock()
    mock_def.model_dump.return_value = {"name": "openai"}
    mock_ctx.auth.get_provider.return_value = mock_def

    result = runner.invoke(cli, ["inspect", "openai", "--json"])
    assert result.exit_code == 0


def test_export(runner, mock_ctx):
    mock_ctx.auth.export.return_value = "export VAR=1"
    result = runner.invoke(cli, ["export", "openai", "--format", "env"])
    assert result.exit_code == 0

    mock_ctx.auth.export.return_value = ""
    result2 = runner.invoke(cli, ["export", "openai", "--format", "env"])
    assert result2.exit_code == 0


def test_export_without_provider(runner, mock_ctx):
    mock_ctx.auth.export.return_value = "OPENAI_API_KEY=sk-test"

    result = runner.invoke(cli, ["export"])

    assert result.exit_code == 0
    assert "OPENAI_API_KEY=sk-test" in result.output
    mock_ctx.auth.export.assert_called_with(None, "default", format=ExportFormat.ENV)


def test_run(runner, mock_ctx):
    mock_ctx.proxy.run.return_value = MagicMock(returncode=0)
    result = runner.invoke(cli, ["run", "--", "echo", "hello"])
    assert result.exit_code == 0
    mock_ctx.proxy.run.assert_called_once_with(["echo", "hello"])


def test_register_file_not_found(runner):
    result = runner.invoke(cli, ["register", "nonexistent.json"])
    assert result.exit_code == 1
    assert "File not found" in result.output


def test_register_success(runner, mock_ctx, tmp_path):
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
    mock_ctx.auth.register_provider.assert_called_once()


def test_register_success_json(runner, mock_ctx, tmp_path):
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


def test_register_bad_json(runner, mock_ctx, tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{bad")
    result = runner.invoke(cli, ["register", str(f)])
    assert result.exit_code == 1


def test_whoami(runner, mock_ctx, tmp_path):
    mock_ctx.home = tmp_path
    result = runner.invoke(cli, ["whoami"])
    assert result.exit_code == 0
    assert str(tmp_path) in result.output
    assert "local_key" in result.output  # default encryption mode


def test_whoami_with_config(runner, mock_ctx, tmp_path):
    mock_ctx.home = tmp_path
    config_data = {"spec_version": 1, "default_profile": "default", "encryption": {"mode": "keyring"}}
    (tmp_path / "config.json").write_text(json.dumps(config_data))

    result = runner.invoke(cli, ["whoami", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["encryption_mode"] == "keyring"


def test_doctor(runner, mock_ctx):
    mock_ctx.doctor.return_value = {
        "home_exists": True,
        "encryption": False,
        "issues": ["error"],
        "providers_count": 0,
    }
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_doctor_json(runner, mock_ctx):
    mock_ctx.doctor.return_value = {
        "home_exists": True,
        "encryption": True,
        "issues": [],
    }
    result = runner.invoke(cli, ["doctor", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["home_exists"] is True


def test_doctor_all_ok(runner, mock_ctx):
    mock_ctx.doctor.return_value = {
        "home_exists": True,
        "encryption": True,
        "issues": [],
        "providers_count": 1,
    }
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_common_options_error_handling_json(runner, mock_ctx):
    mock_ctx.auth.login.side_effect = AuthsomeError("Error")
    result = runner.invoke(cli, ["login", "openai", "--json"])
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert data["error"] == "AuthsomeError"


def test_echo_no_color(runner, mock_ctx):
    result = runner.invoke(cli, ["logout", "openai", "--no-color"])
    assert result.exit_code == 0


def test_echo_quiet(runner, mock_ctx):
    result = runner.invoke(cli, ["logout", "openai", "--quiet"])
    assert result.exit_code == 0
    assert "Logged out" not in result.output
