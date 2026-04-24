"""Tests for the Device Code OAuth flow."""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
from authsome.errors import AuthenticationFailedError
from authsome.flows.device_code import DeviceCodeFlow
from authsome.models.connection import ConnectionStatus
from authsome.models.enums import AuthType, FlowType
from authsome.models.provider import OAuthConfig, ProviderDefinition


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


def test_missing_oauth(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    provider.oauth = None
    flow = DeviceCodeFlow()

    with pytest.raises(AuthenticationFailedError, match="missing 'oauth' configuration"):
        flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_missing_device_url(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    provider.oauth.device_authorization_url = None
    flow = DeviceCodeFlow()

    with pytest.raises(AuthenticationFailedError, match="not have a device_authorization_url"):
        flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_missing_client_id(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = DeviceCodeFlow()

    with pytest.raises(AuthenticationFailedError, match="requires a client_id"):
        flow.authenticate(provider, crypto, "default", "default")


def test_request_device_code_http_error(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = DeviceCodeFlow()

    with patch(
        "authsome.flows.device_code.requests.post",
        side_effect=requests.RequestException("boom"),
    ):
        with pytest.raises(AuthenticationFailedError, match="Device authorization request failed"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_request_device_code_invalid_json(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = DeviceCodeFlow()

    mock_resp = MagicMock()
    mock_resp.json.side_effect = json.JSONDecodeError("msg", "doc", 0)

    with patch("authsome.flows.device_code.requests.post", return_value=mock_resp):
        with pytest.raises(AuthenticationFailedError, match="not valid JSON"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_request_device_code_missing_fields(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = DeviceCodeFlow()

    mock_resp = MagicMock()
    # Missing user_code and verification_uri
    mock_resp.json.return_value = {"device_code": "dc123"}

    with patch("authsome.flows.device_code.requests.post", return_value=mock_resp):
        with pytest.raises(AuthenticationFailedError, match="missing required fields"):
            flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_poll_for_token_timeout(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
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

    with patch("authsome.flows.device_code.requests.post", return_value=device_resp):
        with patch("authsome.flows.device_code.time.sleep"):
            with patch("authsome.flows.device_code.time.monotonic", side_effect=[0, 2]):
                # loop runs once and then deadline is past
                with pytest.raises(AuthenticationFailedError, match="Device authorization timed out"):
                    flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_poll_for_token_success_and_errors(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
    provider = _make_provider()
    flow = DeviceCodeFlow()

    # We will simulate multiple polling attempts
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
        device_resp,  # Phase 1 request
        requests.RequestException("boom"),  # Poll 1: request exception -> loops
        token_json_err,  # Poll 2: json decode error -> loops
        token_pending,  # Poll 3: pending -> loops
        token_slow_down,  # Poll 4: slow down -> interval increases
        token_success,  # Poll 5: success
    ]

    with patch("authsome.flows.device_code.requests.post", side_effect=mock_post_responses):
        with patch("authsome.flows.device_code.time.sleep") as mock_sleep:
            with patch(
                "authsome.flows.device_code.time.monotonic",
                side_effect=[0, 0, 0, 0, 0, 0],
            ):
                record = flow.authenticate(
                    provider,
                    crypto,
                    "default",
                    "default",
                    scopes=["test_scope"],
                    client_id="cid",
                    client_secret="sec",
                )

    assert record.status == ConnectionStatus.CONNECTED
    assert crypto.decrypt(record.access_token) == "acc"
    assert "test_scope" in record.scopes
    # Sleep is called 5 times
    assert mock_sleep.call_count == 5
    # The last sleep should be interval (1) + 5 = 6 due to slow_down
    assert mock_sleep.call_args_list[-1][0][0] == 6


def test_poll_for_token_access_denied(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
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
        "authsome.flows.device_code.requests.post",
        side_effect=[device_resp, token_denied],
    ):
        with patch("authsome.flows.device_code.time.sleep"):
            with patch("authsome.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="User denied"):
                    flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_poll_for_token_expired_token(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
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
        "authsome.flows.device_code.requests.post",
        side_effect=[device_resp, token_expired],
    ):
        with patch("authsome.flows.device_code.time.sleep"):
            with patch("authsome.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="Device code has expired"):
                    flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_poll_for_token_unknown_error(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
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

    with patch("authsome.flows.device_code.requests.post", side_effect=[device_resp, token_err]):
        with patch("authsome.flows.device_code.time.sleep"):
            with patch("authsome.flows.device_code.time.monotonic", side_effect=[0, 0]):
                with pytest.raises(AuthenticationFailedError, match="weird"):
                    flow.authenticate(provider, crypto, "default", "default", client_id="cid")


def test_poll_for_token_success_no_expires_in(tmp_path):
    crypto = LocalFileCryptoBackend(tmp_path)
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
        "authsome.flows.device_code.requests.post",
        side_effect=[device_resp, token_success],
    ):
        with patch("authsome.flows.device_code.time.sleep"):
            with patch("authsome.flows.device_code.time.monotonic", side_effect=[0, 0]):
                record = flow.authenticate(
                    provider,
                    crypto,
                    "default",
                    "default",
                    client_id="cid",
                    client_secret="sec",
                )

    assert record.status == ConnectionStatus.CONNECTED
    assert record.expires_at is None
