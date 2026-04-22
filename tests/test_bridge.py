"""Tests for the browser-based secure input bridge."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import authsome.flows.bridge as bridge


class _FakeServer:
    def __init__(self, addr, handler):
        self.addr = addr
        self.handler = handler

    def serve_forever(self) -> None:
        return None

    def shutdown(self) -> None:
        return None


class _SuccessThread:
    def __init__(self, target=None, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        bridge._BridgeHandler.result = {"api_key": "browser-secret"}


class _TimeoutThread:
    def __init__(self, target=None, daemon=False):
        self.target = target
        self.daemon = daemon

    def start(self) -> None:
        return None

    def join(self, timeout=None) -> None:
        return None


def test_find_free_port_returns_int(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeSocket:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def bind(self, addr):
            return None

        def getsockname(self):
            return ("127.0.0.1", 4321)

    monkeypatch.setattr(bridge.socket, "socket", _FakeSocket)
    assert bridge._find_free_port() == 4321


def test_secure_input_bridge_returns_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_find_free_port", lambda: 4321)
    monkeypatch.setattr(bridge.http.server, "HTTPServer", _FakeServer)
    monkeypatch.setattr(bridge.threading, "Thread", _SuccessThread)
    monkeypatch.setattr(bridge.webbrowser, "open", lambda url: True)

    result = bridge.secure_input_bridge(
        "Secure Input",
        [{"name": "api_key", "label": "API Key", "type": "password"}],
    )

    assert result == {"api_key": "browser-secret"}


def test_secure_input_bridge_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "_find_free_port", lambda: 4321)
    monkeypatch.setattr(bridge.http.server, "HTTPServer", _FakeServer)
    monkeypatch.setattr(bridge.threading, "Thread", _TimeoutThread)
    monkeypatch.setattr(bridge.webbrowser, "open", lambda url: True)

    with pytest.raises(RuntimeError, match="timed out"):
        bridge.secure_input_bridge(
            "Secure Input",
            [{"name": "api_key", "label": "API Key", "type": "password"}],
        )
