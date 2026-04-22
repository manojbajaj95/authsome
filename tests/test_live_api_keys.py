"""Live API-key integration tests using real credentials from the environment."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from authsome.client import AuthClient
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.provider import ApiKeyConfig, ProviderDefinition


LIVE_PROVIDERS: list[tuple[str, str, str, str]] = [
    ("resend", "RESEND_API_KEY", "Authorization", "Bearer"),
    ("klaviyo", "KLAVIYO_API_KEY", "Authorization", "Klaviyo-API-Key"),
]


def _env_value(name: str) -> str | None:
    value = os.environ.get(name)
    if value is not None:
        value = value.strip()
    return value or None


def _available_live_cases() -> list[tuple[str, str, str, str]]:
    return [case for case in LIVE_PROVIDERS if _env_value(case[1])]


pytestmark = pytest.mark.skipif(
    not _available_live_cases(),
    reason="Live API-key credentials were not provided for this session.",
)


def _make_provider(name: str, env_var: str, header_name: str, header_prefix: str) -> ProviderDefinition:
    return ProviderDefinition(
        name=name,
        display_name=name.replace("-", " ").title(),
        auth_type=AuthType.API_KEY,
        flow=FlowType.API_KEY,
        api_key=ApiKeyConfig(
            header_name=header_name,
            header_prefix=header_prefix,
        ),
    )


@pytest.fixture
def client(tmp_path: Path) -> AuthClient:
    home = tmp_path / ".authsome"
    c = AuthClient(home=home)
    c.init()
    yield c
    c.close()


@pytest.mark.parametrize(("provider_name", "env_var", "header_name", "header_prefix"), _available_live_cases())
def test_live_api_key_login_export_and_headers(
    client: AuthClient,
    provider_name: str,
    env_var: str,
    header_name: str,
    header_prefix: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if provider_name in {provider.name for provider in client.list_providers()}:
        provider = client.get_provider(provider_name).model_copy(
            update={
                "flow": FlowType.API_KEY,
                "api_key": ApiKeyConfig(header_name=header_name, header_prefix=header_prefix),
            }
        )
    else:
        provider = _make_provider(provider_name, env_var, header_name, header_prefix)

    client.register_provider(provider, force=True)

    live_secret = _env_value(env_var)
    assert live_secret is not None
    monkeypatch.setattr(
        "authsome.flows.bridge.secure_input_bridge",
        lambda title, fields: {"api_key": live_secret},
    )

    record = client.login(provider_name)

    assert record.status == ConnectionStatus.CONNECTED
    assert record.api_key is not None
    assert client.get_access_token(provider_name) == live_secret

    headers = client.get_auth_headers(provider_name)
    if header_prefix:
        assert headers[header_name] == f"{header_prefix} {live_secret}"
    else:
        assert headers[header_name] == live_secret

    exported_env = client.export(provider_name, format=ExportFormat.ENV)
    assert live_secret in exported_env

    exported_json = client.export(provider_name, format=ExportFormat.JSON)
    assert live_secret in exported_json


def test_live_connections_are_listed(client: AuthClient, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = _available_live_cases()
    assert cases

    for provider_name, env_var, header_name, header_prefix in cases[:2]:
        if provider_name in {provider.name for provider in client.list_providers()}:
            provider = client.get_provider(provider_name).model_copy(
                update={
                    "flow": FlowType.API_KEY,
                    "api_key": ApiKeyConfig(header_name=header_name, header_prefix=header_prefix),
                }
            )
        else:
            provider = _make_provider(provider_name, env_var, header_name, header_prefix)
        client.register_provider(provider, force=True)
        live_secret = _env_value(env_var)
        assert live_secret is not None
        monkeypatch.setattr(
            "authsome.flows.bridge.secure_input_bridge",
            lambda title, fields, secret=live_secret: {"api_key": secret},
        )
        client.login(provider_name)

    connections = client.list_connections()
    names = {entry["name"] for entry in connections}
    assert names
