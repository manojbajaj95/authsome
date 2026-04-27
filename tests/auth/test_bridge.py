"""Tests for the secure browser bridge."""

import urllib.parse
import urllib.request
from unittest.mock import patch

import pytest

from authsome.auth.flows.bridge import _BridgeHandler, _find_free_port, secure_input_bridge


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
