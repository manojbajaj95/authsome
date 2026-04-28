"""Tests for the secure browser bridge."""

import urllib.parse
import urllib.request
from unittest.mock import patch

import pytest

from authsome.auth.flows.bridge import (
    _BridgeHandler,
    _find_free_port,
    device_code_bridge,
    secure_input_bridge,
)


def test_find_free_port():
    port = _find_free_port()
    assert isinstance(port, int)
    assert port > 0


def test_secure_input_bridge_success():
    fields = [
        {
            "type": "instructions",
            "label": "Instructions",
            "url": "https://example.com/oauth-app",
        },
        {"name": "api_key", "label": "API Key", "type": "password"},
        {"name": "username", "label": "Username", "required": False},
    ]

    def mock_open(url):
        # 1. Test GET
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            assert response.status == 200
            html = response.read().decode("utf-8")
            assert "Test Auth" in html
            assert "Instructions" in html
            assert "Read setup docs" in html
            assert "https://example.com/oauth-app" in html
            assert "API Key" in html
            assert "Username" in html

        # 2. Test POST
        data = urllib.parse.urlencode({"api_key": "secret123", "username": "testuser"}).encode("utf-8")
        req_post = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req_post) as response:
            assert response.status == 200
            html = response.read().decode("utf-8")
            assert "Success!" in html

    with patch("authsome.auth.flows.bridge.webbrowser.open", side_effect=mock_open):
        res = secure_input_bridge("Test Auth", fields)

    assert res == {"api_key": "secret123", "username": "testuser"}


def test_secure_input_bridge_timeout():
    fields = [{"name": "key", "label": "Key"}]

    def mock_open(url):
        pass

    with patch("authsome.auth.flows.bridge.webbrowser.open", side_effect=mock_open):
        with patch("threading.Thread.join"):
            with pytest.raises(RuntimeError, match="timed out or was cancelled"):
                secure_input_bridge("Test Auth", fields)


def test_log_message():
    handler = _BridgeHandler.__new__(_BridgeHandler)
    handler.log_message("test %s", "arg")


def test_device_code_bridge_renders_url_and_code():
    """Browser sees the user code, verification URL, and copy button."""
    captured: dict[str, str] = {}

    def fake_open(url: str) -> bool:
        captured["url"] = url
        with urllib.request.urlopen(url) as response:
            assert response.status == 200
            captured["html"] = response.read().decode("utf-8")
        return True

    with patch("authsome.auth.flows.bridge.webbrowser.open", side_effect=fake_open):
        handle = device_code_bridge(
            title="Postiz — Device Authorization",
            user_code="WDJB-MJHT",
            verification_uri="https://postiz.example.com/device",
            verification_uri_complete="https://postiz.example.com/device?code=WDJB-MJHT",
        )

    try:
        html = captured["html"]
        assert "Postiz — Device Authorization" in html
        assert "WDJB-MJHT" in html
        assert "postiz.example.com/device?code=WDJB-MJHT" in html
        assert "Copy" in html
    finally:
        handle.shutdown()


def test_device_code_bridge_open_browser_failure_is_swallowed():
    """If webbrowser.open raises, the bridge still starts and remains usable."""
    with patch("authsome.auth.flows.bridge.webbrowser.open", side_effect=RuntimeError("nope")):
        handle = device_code_bridge(
            title="Test",
            user_code="ABCD-1234",
            verification_uri="https://example.com/device",
        )
    try:
        with urllib.request.urlopen(handle.url) as response:
            assert response.status == 200
    finally:
        handle.shutdown()


def test_device_code_bridge_shutdown_is_idempotent():
    with patch("authsome.auth.flows.bridge.webbrowser.open"):
        handle = device_code_bridge(
            title="Test",
            user_code="X",
            verification_uri="https://example.com/device",
        )
    handle.shutdown()
    handle.shutdown()  # second call must be a no-op
