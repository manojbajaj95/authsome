"""Tests for the PKCE OAuth flow."""

import json
import urllib.parse
import urllib.request
from unittest.mock import MagicMock, patch

import pytest
import requests

from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
from authsome.errors import AuthenticationFailedError
from authsome.flows.pkce import (
    PkceFlow,
    _CallbackHandler,
    _find_free_port,
    _generate_pkce,
)
from authsome.models.connection import ConnectionStatus
from authsome.models.enums import AuthType, FlowType
from authsome.models.provider import OAuthConfig, ProviderDefinition


def _make_provider() -> ProviderDefinition:
    return ProviderDefinition(
        name="testoauth",
        display_name="Test OAuth",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            authorization_url="https://auth.example.com/auth",
            token_url="https://auth.example.com/token",
        ),
    )


def test_find_free_port():
    port = _find_free_port()
    assert isinstance(port, int)
    assert port > 0


def test_generate_pkce():
    verifier, challenge = _generate_pkce()
    assert len(verifier) >= 43
    assert len(challenge) >= 43


def test_missing_oauth(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    provider.oauth = None
    flow = PkceFlow()

    with pytest.raises(AuthenticationFailedError, match="missing 'oauth' configuration"):
        flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_missing_client_id(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()

    with pytest.raises(AuthenticationFailedError, match="requires a client_id"):
        flow.authenticate(provider, crypto, "default", "default")


def test_callback_handler_log():
    handler = _CallbackHandler.__new__(_CallbackHandler)
    handler.log_message("test %s", "msg")


def test_pkce_flow_success(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        # Extract state from URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        state = params["state"][0]

        # Send callback
        callback_url = f"http://127.0.0.1:{port}/callback?code=mock_code&state={state}"
        req = urllib.request.Request(callback_url)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "access_token": "mock_access",
        "refresh_token": "mock_refresh",
        "expires_in": 3600,
    }

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch("authsome.flows.pkce.http_client.post", return_value=mock_resp) as mock_post:
            record = flow.authenticate(
                provider,
                crypto,
                "default",
                "default",
                scopes=["read", "write"],
                client_id="cid",
                client_secret="sec",
            )

    assert record.status == ConnectionStatus.CONNECTED
    assert "read" in record.scopes
    assert crypto.decrypt(record.access_token) == "mock_access"
    assert crypto.decrypt(record.refresh_token) == "mock_refresh"
    assert record.expires_at is not None
    mock_post.assert_called_once()


def test_pkce_flow_callback_error(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        callback_url = f"http://127.0.0.1:{port}/callback?error=access_denied&error_description=User%20denied"
        req = urllib.request.Request(callback_url)
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with pytest.raises(AuthenticationFailedError, match="access_denied"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_flow_callback_invalid(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        # Missing code
        callback_url = f"http://127.0.0.1:{port}/callback?other=123"
        req = urllib.request.Request(callback_url)
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            assert e.code == 400

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with pytest.raises(AuthenticationFailedError, match="no code received"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_flow_state_mismatch(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        # Wrong state
        callback_url = f"http://127.0.0.1:{port}/callback?code=mock_code&state=wrong_state"
        req = urllib.request.Request(callback_url)
        with urllib.request.urlopen(req) as _:
            pass

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with pytest.raises(AuthenticationFailedError, match="state mismatch"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_exchange_http_error(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        parsed = urllib.parse.urlparse(url)
        state = urllib.parse.parse_qs(parsed.query)["state"][0]
        callback_url = f"http://127.0.0.1:{port}/callback?code=mock_code&state={state}"
        urllib.request.urlopen(urllib.request.Request(callback_url))

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch(
            "authsome.flows.pkce.http_client.post",
            side_effect=requests.RequestException("boom"),
        ):
            with pytest.raises(AuthenticationFailedError, match="Token exchange failed: boom"):
                flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_exchange_invalid_json(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        parsed = urllib.parse.urlparse(url)
        state = urllib.parse.parse_qs(parsed.query)["state"][0]
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/callback?code=mock_code&state={state}"))

    mock_resp = MagicMock()
    mock_resp.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch("authsome.flows.pkce.http_client.post", return_value=mock_resp):
            with pytest.raises(AuthenticationFailedError, match="Token response was not valid JSON"):
                flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_exchange_missing_access_token(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        parsed = urllib.parse.urlparse(url)
        state = urllib.parse.parse_qs(parsed.query)["state"][0]
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/callback?code=mock_code&state={state}"))

    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "error": "invalid_grant",
        "error_description": "bad code",
    }

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch("authsome.flows.pkce.http_client.post", return_value=mock_resp):
            with pytest.raises(AuthenticationFailedError, match="bad code"):
                flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_flow_no_scopes(tmp_path):
    # Test missing scopes to hit line 161
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    # Ensure no scopes are set
    provider.oauth.scopes = None
    flow = PkceFlow()
    flow.callback_port = _find_free_port()
    port = flow.callback_port

    def mock_open(url):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        assert "scope" not in params
        state = params["state"][0]
        callback_url = f"http://127.0.0.1:{port}/callback?code=mock_code&state={state}"
        req = urllib.request.Request(callback_url)
        urllib.request.urlopen(req)

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"access_token": "mock"}

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch("authsome.flows.pkce.http_client.post", return_value=mock_resp):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_pkce_flow_timeout(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = PkceFlow()
    flow.callback_port = _find_free_port()

    def mock_open(url):
        # Do nothing to simulate timeout
        pass

    with patch("authsome.flows.pkce.webbrowser.open", side_effect=mock_open):
        with patch("authsome.flows.pkce._CALLBACK_TIMEOUT_SECONDS", 0.01):
            with pytest.raises(AuthenticationFailedError, match="timed out"):
                flow.authenticate(provider, crypto, "default", "default", client_id="cid")
