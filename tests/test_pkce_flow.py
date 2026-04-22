"""Tests for the PKCE OAuth flow."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

import authsome.flows.pkce as pkce
from authsome.crypto.base import EncryptedField
from authsome.errors import AuthenticationFailedError
from authsome.flows.pkce import PkceFlow
from authsome.models.enums import AuthType, ConnectionStatus, FlowType
from authsome.models.provider import OAuthConfig, ProviderDefinition


class _FakeServer:
    def __init__(self, addr, handler):
        self.addr = addr
        self.handler = handler
        self.closed = False

    def handle_request(self) -> None:
        return None

    def server_close(self) -> None:
        self.closed = True


class _SuccessThread:
    def __init__(self, target=None, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        pkce._CallbackHandler.auth_code = "auth-code"
        pkce._CallbackHandler.state = "oauth-state"


class _TimeoutThread:
    def __init__(self, target=None, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        return None


class _FakeResponse:
    def __init__(self, payload: dict[str, str]):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, str]:
        return self.payload


class _FakeCrypto:
    def __init__(self) -> None:
        self.encrypted: list[str | None] = []

    def encrypt(self, value: str | None) -> EncryptedField:
        self.encrypted.append(value)
        assert value is not None
        return EncryptedField(
            nonce="nonce",
            ciphertext="ciphertext",
            tag="tag",
        )


def _make_provider(name: str = "flow-oauth") -> ProviderDefinition:
    return ProviderDefinition(
        name=name,
        display_name="Flow OAuth",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            authorization_url="https://example.com/auth",
            token_url="https://example.com/token",
            scopes=["accounts:read"],
        ),
    )


def test_pkce_flow_authenticate_success(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _make_provider()
    crypto = _FakeCrypto()
    flow = PkceFlow()

    monkeypatch.setattr(pkce, "_generate_pkce", lambda: ("verifier", "challenge"))
    monkeypatch.setattr(pkce.http.server, "HTTPServer", _FakeServer)
    monkeypatch.setattr(pkce.threading, "Thread", _SuccessThread)
    monkeypatch.setattr(pkce.secrets, "token_urlsafe", lambda n: "oauth-state")
    monkeypatch.setattr(pkce.webbrowser, "open", lambda url: True)
    monkeypatch.setattr(
        pkce.http_client,
        "post",
        lambda *args, **kwargs: _FakeResponse(
            {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "token_type": "Bearer",
                "expires_in": "3600",
            }
        ),
    )
    monkeypatch.setattr(pkce, "utc_now", lambda: datetime(2026, 4, 22, tzinfo=UTC))

    record = flow.authenticate(
        provider=provider,
        crypto=crypto,
        profile="default",
        connection_name="default",
        client_id="client-id",
        client_secret="client-secret",
    )

    assert record.provider == "flow-oauth"
    assert record.status == ConnectionStatus.CONNECTED
    assert record.access_token is not None
    assert record.refresh_token is not None
    assert crypto.encrypted == ["access-token", "refresh-token"]
    assert record.expires_at == datetime(2026, 4, 22, 1, 0, tzinfo=UTC)


def test_pkce_flow_requires_client_id(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _make_provider()
    flow = PkceFlow()

    with pytest.raises(AuthenticationFailedError, match="requires a client_id"):
        flow.authenticate(
            provider=provider,
            crypto=_FakeCrypto(),
            profile="default",
            connection_name="default",
        )


def test_pkce_flow_state_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = _make_provider()
    flow = PkceFlow()

    monkeypatch.setattr(pkce, "_generate_pkce", lambda: ("verifier", "challenge"))
    monkeypatch.setattr(pkce.http.server, "HTTPServer", _FakeServer)
    monkeypatch.setattr(pkce.threading, "Thread", _TimeoutThread)
    monkeypatch.setattr(pkce.secrets, "token_urlsafe", lambda n: "oauth-state")
    monkeypatch.setattr(pkce.webbrowser, "open", lambda url: True)

    with pytest.raises(AuthenticationFailedError, match="timed out or no code received"):
        flow.authenticate(
            provider=provider,
            crypto=_FakeCrypto(),
            profile="default",
            connection_name="default",
            client_id="client-id",
            client_secret="client-secret",
        )
