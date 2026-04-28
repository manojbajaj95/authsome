"""Tests for the Device Code OAuth flow."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from authsome.auth.flows.device_code import DeviceCodeFlow
from authsome.auth.models.connection import ConnectionStatus
from authsome.auth.models.enums import AuthType, FlowType
from authsome.auth.models.provider import OAuthConfig, ProviderDefinition
from authsome.errors import AuthenticationFailedError


@pytest.fixture(autouse=True)
def _stub_device_code_bridge():
    """Prevent DeviceCodeFlow from spawning a real HTTP bridge / opening a browser."""
    with patch("authsome.auth.flows.device_code.device_code_bridge") as mock_bridge:
        mock_bridge.return_value = MagicMock(url="http://127.0.0.1:0", shutdown=MagicMock())
        yield mock_bridge


def _make_provider() -> ProviderDefinition:
    return ProviderDefinition(
        name="testdevice",
        display_name="Test Device",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.DEVICE_CODE,
        oauth=OAuthConfig(
            authorization_url="https://auth.example.com/auth",
            device_authorization_url="https://auth.example.com/device",
            token_url="https://auth.example.com/token",
        ),
    )


def test_missing_oauth():
    provider = _make_provider()
    provider.oauth = None
    flow = DeviceCodeFlow()

    with pytest.raises(AuthenticationFailedError, match="missing 'oauth' configuration"):
        flow.authenticate(provider, "default", "default", client_id="cid")


def test_missing_device_url():
    provider = _make_provider()
    provider.oauth.device_authorization_url = None
    flow = DeviceCodeFlow()

    with pytest.raises(AuthenticationFailedError, match="not have a device_authorization_url"):
        flow.authenticate(provider, "default", "default", client_id="cid")


def test_authenticate_without_client_id_succeeds():
    """Device flow allows omitted client_id for public / mediated providers."""
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }
    token_success = MagicMock()
    token_success.status_code = 200
    token_success.json.return_value = {"access_token": "acc"}

    with patch("authsome.auth.flows.device_code.requests.post", side_effect=[device_resp, token_success]):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                result = flow.authenticate(provider, "default", "default", client_id=None, scopes=None)

    assert result.connection.status == ConnectionStatus.CONNECTED
    assert result.connection.access_token == "acc"


def test_json_device_token_request_uses_json_body():
    provider = _make_provider()
    assert provider.oauth is not None
    provider.oauth.device_token_request = "json"
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }
    token_success = MagicMock()
    token_success.status_code = 200
    token_success.json.return_value = {"access_token": "tok"}

    mock_post = MagicMock(side_effect=[device_resp, token_success])
    with patch("authsome.auth.flows.device_code.requests.post", mock_post):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                flow.authenticate(provider, "default", "default", client_id=None)

    assert mock_post.call_count == 2
    second = mock_post.call_args_list[1]
    assert second.kwargs.get("json") == {"device_code": "dc"}
    assert "data" not in second.kwargs or second.kwargs.get("data") is None


def test_request_device_code_http_error():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    with patch(
        "authsome.auth.flows.device_code.requests.post",
        side_effect=requests.RequestException("boom"),
    ):
        with pytest.raises(AuthenticationFailedError, match="Device authorization request failed"):
            flow.authenticate(provider, "default", "default", client_id="cid")


def test_request_device_code_invalid_json():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    mock_resp = MagicMock()
    mock_resp.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

    with patch("authsome.auth.flows.device_code.requests.post", return_value=mock_resp):
        with pytest.raises(AuthenticationFailedError, match="not valid JSON"):
            flow.authenticate(provider, "default", "default", client_id="cid")


def test_request_device_code_missing_fields():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"device_code": "dc123"}

    with patch("authsome.auth.flows.device_code.requests.post", return_value=mock_resp):
        with pytest.raises(AuthenticationFailedError, match="missing required fields"):
            flow.authenticate(provider, "default", "default", client_id="cid")


def test_poll_for_token_timeout():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 1,
        "interval": 1,
    }

    with patch("authsome.auth.flows.device_code.requests.post", return_value=device_resp):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 2]):
                with pytest.raises(AuthenticationFailedError, match="Device authorization timed out"):
                    flow.authenticate(provider, "default", "default", client_id="cid")


def test_poll_for_token_success_and_errors():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "verification_uri_complete": "http://uri?user_code=uc",
        "expires_in": 300,
        "interval": 1,
    }

    token_json_err = MagicMock()
    token_json_err.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

    token_pending = MagicMock()
    token_pending.status_code = 400
    token_pending.json.return_value = {"error": "authorization_pending"}

    token_slow_down = MagicMock()
    token_slow_down.status_code = 400
    token_slow_down.json.return_value = {"error": "slow_down"}

    token_success = MagicMock()
    token_success.status_code = 200
    token_success.json.return_value = {
        "access_token": "acc",
        "refresh_token": "ref",
        "expires_in": 3600,
    }

    mock_post_responses = [
        device_resp,
        requests.RequestException("boom"),
        token_json_err,
        token_pending,
        token_slow_down,
        token_success,
    ]

    with patch("authsome.auth.flows.device_code.requests.post", side_effect=mock_post_responses):
        with patch("authsome.auth.flows.device_code.time.sleep") as mock_sleep:
            with patch(
                "authsome.auth.flows.device_code.time.monotonic",
                side_effect=[0, 0, 0, 0, 0, 0],
            ):
                result = flow.authenticate(
                    provider,
                    "default",
                    "default",
                    scopes=["test_scope"],
                    client_id="cid",
                    client_secret="sec",
                )
        record = result.connection

    assert record.status == ConnectionStatus.CONNECTED
    # Tokens are plaintext in v2
    assert record.access_token == "acc"
    assert "test_scope" in record.scopes
    assert mock_sleep.call_count == 5
    assert mock_sleep.call_args_list[-1][0][0] == 6


def test_poll_for_token_access_denied():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }

    token_denied = MagicMock()
    token_denied.status_code = 400
    token_denied.json.return_value = {"error": "access_denied"}

    with patch(
        "authsome.auth.flows.device_code.requests.post",
        side_effect=[device_resp, token_denied],
    ):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="User denied"):
                    flow.authenticate(provider, "default", "default", client_id="cid")


def test_poll_for_token_expired_token():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }

    token_expired = MagicMock()
    token_expired.status_code = 400
    token_expired.json.return_value = {"error": "expired_token"}

    with patch(
        "authsome.auth.flows.device_code.requests.post",
        side_effect=[device_resp, token_expired],
    ):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="Device code has expired"):
                    flow.authenticate(provider, "default", "default", client_id="cid")


def test_poll_for_token_unknown_error():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }

    token_err = MagicMock()
    token_err.status_code = 400
    token_err.json.return_value = {
        "error": "unknown_error",
        "error_description": "weird",
    }

    with patch("authsome.auth.flows.device_code.requests.post", side_effect=[device_resp, token_err]):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="weird"):
                    flow.authenticate(provider, "default", "default", client_id="cid")


def test_poll_for_token_success_no_expires_in():
    provider = _make_provider()
    flow = DeviceCodeFlow()

    device_resp = MagicMock()
    device_resp.json.return_value = {
        "device_code": "dc",
        "user_code": "uc",
        "verification_uri": "http://uri",
        "expires_in": 300,
        "interval": 1,
    }

    token_success = MagicMock()
    token_success.status_code = 200
    token_success.json.return_value = {"access_token": "acc", "refresh_token": "ref"}

    with patch(
        "authsome.auth.flows.device_code.requests.post",
        side_effect=[device_resp, token_success],
    ):
        with patch("authsome.auth.flows.device_code.time.sleep"):
            with patch("authsome.auth.flows.device_code.time.monotonic", side_effect=[0, 0]):
                result = flow.authenticate(
                    provider,
                    "default",
                    "default",
                    client_id="cid",
                    client_secret="sec",
                )

    assert result.connection.status == ConnectionStatus.CONNECTED
    assert result.connection.expires_at is None
