"""Tests for the Click CLI wrapper."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from types import MethodType

from click.testing import CliRunner

import authsome.cli as cli_module
from authsome.errors import ProviderNotFoundError
from authsome.models.config import GlobalConfig
from authsome.models.connection import ConnectionRecord
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.provider import ApiKeyConfig, ProviderDefinition
from authsome.crypto.local_file_crypto import LocalFileCryptoBackend


class DummyClient:
    """Small stand-in for AuthClient used by CLI tests."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.config = GlobalConfig()
        self.crypto = LocalFileCryptoBackend(home / "crypto")
        self.calls: list[tuple] = []

        self.providers = {
            "openai": ProviderDefinition(
                name="openai",
                display_name="OpenAI",
                auth_type=AuthType.API_KEY,
                flow=FlowType.API_KEY,
                api_key=ApiKeyConfig(),
            ),
            "custom": ProviderDefinition(
                name="custom",
                display_name="Custom Provider",
                auth_type=AuthType.API_KEY,
                flow=FlowType.API_KEY,
                api_key=ApiKeyConfig(),
            ),
        }

        secret = self.crypto.encrypt("sk-test-123")
        self.connection = ConnectionRecord(
            provider="openai",
            profile="default",
            connection_name="default",
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key=secret,
        )

    def init(self) -> None:
        self.calls.append(("init",))
        self.home.mkdir(parents=True, exist_ok=True)

    def list_connections(self) -> list[dict]:
        return [
            {
                "name": "openai",
                "connections": [
                    {
                        "connection_name": "default",
                        "auth_type": "api_key",
                        "status": "connected",
                        "scopes": ["repo"],
                        "expires_at": None,
                    }
                ],
            }
        ]

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        return {"bundled": [self.providers["openai"]], "custom": [self.providers["custom"]]}

    def get_provider(self, name: str) -> ProviderDefinition:
        if name not in self.providers:
            raise ProviderNotFoundError(name)
        return self.providers[name]

    def get_connection(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> ConnectionRecord:
        if provider != "openai":
            raise ProviderNotFoundError(provider)
        return self.connection

    def login(
        self,
        provider: str,
        connection_name: str = "default",
        scopes: list[str] | None = None,
        flow_override: FlowType | None = None,
        profile: str | None = None,
        force: bool = False,
    ) -> ConnectionRecord:
        self.calls.append(("login", provider, connection_name, scopes, flow_override, profile, force))
        return self.connection

    def logout(self, provider: str, connection: str = "default", profile: str | None = None) -> None:
        self.calls.append(("logout", provider, connection, profile))

    def revoke(self, provider: str, profile: str | None = None) -> None:
        self.calls.append(("revoke", provider, profile))

    def remove(self, provider: str, profile: str | None = None) -> None:
        self.calls.append(("remove", provider, profile))

    def export(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
        format: ExportFormat = ExportFormat.ENV,
    ) -> str:
        self.calls.append(("export", provider, connection, profile, format))
        if format == ExportFormat.JSON:
            return json.dumps({"OPENAI_API_KEY": "sk-test-123"}, indent=2)
        if format == ExportFormat.SHELL:
            return "export OPENAI_API_KEY=sk-test-123"
        return "OPENAI_API_KEY=sk-test-123"

    def run(
        self,
        command: list[str],
        providers: list[str] | None = None,
        profile: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(("run", command, providers, profile))
        return subprocess.CompletedProcess(args=command, returncode=7)

    def register_provider(self, definition: ProviderDefinition, force: bool = False) -> None:
        self.calls.append(("register_provider", definition.name, force))
        self.providers[definition.name] = definition

    def doctor(self) -> dict[str, object]:
        self.calls.append(("doctor",))
        return {
            "home_exists": True,
            "version_file": True,
            "config_file": True,
            "providers_dir": True,
            "profiles_dir": True,
            "encryption": True,
            "store": True,
            "providers_count": 2,
            "profiles_count": 1,
            "issues": [],
        }


def _patch_cli_client(monkeypatch, client: DummyClient) -> None:
    monkeypatch.setattr(cli_module, "AuthClient", lambda: client)


def test_cli_core_commands(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    client = DummyClient(tmp_path / ".authsome")
    _patch_cli_client(monkeypatch, client)

    result = runner.invoke(cli_module.cli, ["init", "--json"])
    assert result.exit_code == 0
    assert '"status": "initialized"' in result.output

    result = runner.invoke(cli_module.cli, ["whoami", "--json"])
    assert result.exit_code == 0
    assert '"encryption_mode": "local_key"' in result.output

    result = runner.invoke(cli_module.cli, ["list"])
    assert result.exit_code == 0
    assert "Bundled Providers" in result.output
    assert "OpenAI" in result.output
    assert "Custom Provider" in result.output

    result = runner.invoke(cli_module.cli, ["inspect", "openai", "--json"])
    assert result.exit_code == 0
    assert '"name": "openai"' in result.output

    result = runner.invoke(cli_module.cli, ["get", "openai"])
    assert result.exit_code == 0
    assert "***REDACTED***" in result.output

    result = runner.invoke(cli_module.cli, ["get", "openai", "--show-secret", "--field", "api_key"])
    assert result.exit_code == 0
    assert "sk-test-123" in result.output

    result = runner.invoke(cli_module.cli, ["export", "openai", "--format", "json"])
    assert result.exit_code == 0
    assert json.loads(result.output) == {"OPENAI_API_KEY": "sk-test-123"}

    result = runner.invoke(cli_module.cli, ["run", "--provider", "openai", "echo", "hello"])
    assert result.exit_code == 7
    assert ("run", ["echo", "hello"], ["openai"], None) in client.calls


def test_cli_lifecycle_commands(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    client = DummyClient(tmp_path / ".authsome")
    _patch_cli_client(monkeypatch, client)

    result = runner.invoke(
        cli_module.cli,
        ["login", "openai", "--json", "--flow", "api_key", "--scopes", "repo,read"],
    )
    assert result.exit_code == 0
    assert '"status": "success"' in result.output
    assert client.calls[-1][0] == "login"
    assert client.calls[-1][3] == ["repo", "read"]

    result = runner.invoke(cli_module.cli, ["login", "openai", "--force"])
    assert result.exit_code == 0
    assert "Warning: Forcing login" in result.output

    result = runner.invoke(cli_module.cli, ["logout", "openai", "--json"])
    assert result.exit_code == 0
    assert '"status": "logged_out"' in result.output

    result = runner.invoke(cli_module.cli, ["revoke", "openai", "--json"])
    assert result.exit_code == 0
    assert '"status": "revoked"' in result.output

    result = runner.invoke(cli_module.cli, ["remove", "custom", "--json"])
    assert result.exit_code == 0
    assert '"status": "removed"' in result.output

    provider_file = tmp_path / "provider.json"
    provider_file.write_text(
        json.dumps(
            ProviderDefinition(
                name="localcli",
                display_name="Local CLI",
                auth_type=AuthType.API_KEY,
                flow=FlowType.API_KEY,
                api_key=ApiKeyConfig(),
            ).model_dump(mode="json"),
            indent=2,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(cli_module.cli, ["register", str(provider_file), "--json"])
    assert result.exit_code == 0
    assert '"status": "registered"' in result.output

    result = runner.invoke(cli_module.cli, ["doctor", "--json"])
    assert result.exit_code == 0
    assert '"providers_count": 2' in result.output


def test_cli_error_paths(tmp_path: Path, monkeypatch) -> None:
    runner = CliRunner()
    client = DummyClient(tmp_path / ".authsome")
    _patch_cli_client(monkeypatch, client)

    def missing_login(*args, **kwargs):
        raise ProviderNotFoundError("missing")

    client.login = MethodType(missing_login, client)  # type: ignore[assignment]

    result = runner.invoke(cli_module.cli, ["--json", "login", "missing"])
    assert result.exit_code == 3
    assert '"error": "ProviderNotFoundError"' in result.output

    result = runner.invoke(cli_module.cli, ["register", str(tmp_path / "missing.json")])
    assert result.exit_code == 1
    assert "File not found" in result.output

    def missing_field(*args, **kwargs):
        return client.connection

    client.get_connection = MethodType(missing_field, client)  # type: ignore[assignment]
    result = runner.invoke(cli_module.cli, ["get", "openai", "--field", "missing"])
    assert result.exit_code == 1
    assert "Field 'missing' not found" in result.output
