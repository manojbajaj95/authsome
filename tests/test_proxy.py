"""Tests for the HTTP proxy injection feature.

Covers:
- Router host matching, loopback rejection, auth endpoint rejection, ambiguity
- Addon header injection and header preservation
- Runner proxy environment setup and shutdown semantics
- Provider metadata parsing for proxy match_hosts
- CLI proxy run command
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from authsome.client import AuthClient
from authsome.proxy.router import RequestRouter, RouteMatch
from authsome.proxy.server import AuthProxyAddon

# ── Router tests ─────────────────────────────────────────────────────────


class TestRequestRouter:
    """RequestRouter matching and rejection behaviour."""

    def test_router_matches_provider_host(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        # Login so the router finds a connection for openai
        with patch("authsome.flows.bridge.secure_input_bridge", return_value={"api_key": "sk-test"}):
            client.login("openai", force=True)

        router = RequestRouter(client)
        match = router.route("https", "api.openai.com", 443, "/v1/responses")

        assert match == RouteMatch(provider="openai", connection="default")

    def test_router_rejects_loopback_host(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        router = RequestRouter(client)

        assert router.route("http", "127.0.0.1", 8080, "/anything") is None
        assert router.route("http", "localhost", 8080, "/anything") is None

    def test_router_rejects_provider_token_endpoint(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        router = RequestRouter(client)

        # github.com hosts both the token endpoint and the API — the token URL
        # should be rejected even though the host matches.
        assert router.route("https", "github.com", 443, "/login/oauth/access_token") is None

    def test_router_no_match_for_unknown_host(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        router = RequestRouter(client)

        assert router.route("https", "unknown.example.com", 443, "/v1") is None

    def test_router_no_match_without_connection(self, tmp_path: Path) -> None:
        """Provider with match_hosts but no stored connection should not match."""
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        # openai has match_hosts configured but no login performed
        router = RequestRouter(client)
        match = router.route("https", "api.openai.com", 443, "/v1/responses")

        assert match is None


# ── Addon tests ──────────────────────────────────────────────────────────


class TestAuthProxyAddon:
    """AuthProxyAddon header injection and passthrough."""

    def test_addon_injects_headers_for_matched_request(self) -> None:
        client = Mock()
        client.get_auth_headers.return_value = {"Authorization": "Bearer sk-test"}
        router = Mock()
        router.route.return_value = RouteMatch(provider="openai", connection="default")
        flow = Mock()
        flow.request.scheme = "https"
        flow.request.host = "api.openai.com"
        flow.request.port = 443
        flow.request.path = "/v1/responses"
        flow.request.headers = {}

        addon = AuthProxyAddon(client=client, router=router)
        addon.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-test"

    def test_addon_overwrites_existing_authorization_header(self) -> None:
        client = Mock()
        client.get_auth_headers.return_value = {"Authorization": "Bearer sk-authsome"}
        router = Mock()
        router.route.return_value = RouteMatch(provider="openai", connection="default")
        flow = Mock()
        flow.request.scheme = "https"
        flow.request.host = "api.openai.com"
        flow.request.port = 443
        flow.request.path = "/v1/responses"
        flow.request.headers = {"Authorization": "Bearer existing"}

        addon = AuthProxyAddon(client=client, router=router)
        addon.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-authsome"

    def test_addon_skips_unmatched_request(self) -> None:
        client = Mock()
        router = Mock()
        router.route.return_value = None
        flow = Mock()
        flow.request.scheme = "https"
        flow.request.host = "example.com"
        flow.request.port = 443
        flow.request.path = "/"
        flow.request.headers = {}

        addon = AuthProxyAddon(client=client, router=router)
        addon.request(flow)

        client.get_auth_headers.assert_not_called()

    def test_addon_continues_on_header_retrieval_failure(self) -> None:
        client = Mock()
        client.get_auth_headers.side_effect = RuntimeError("token expired")
        router = Mock()
        router.route.return_value = RouteMatch(provider="openai", connection="default")
        flow = Mock()
        flow.request.scheme = "https"
        flow.request.host = "api.openai.com"
        flow.request.port = 443
        flow.request.path = "/v1/responses"
        flow.request.headers = {}

        addon = AuthProxyAddon(client=client, router=router)
        addon.request(flow)

        # Should not crash, and no headers should be injected
        assert "Authorization" not in flow.request.headers


# ── Runner tests ─────────────────────────────────────────────────────────


class TestProxyRunner:
    """ProxyRunner subprocess environment and lifecycle."""

    def test_runner_sets_proxy_environment(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        runner = ProxyRunner(client)

        with patch("authsome.proxy.runner.subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", Mock())):
                runner.run(["python", "-c", "print('ok')"])

        env = run_mock.call_args.kwargs["env"]
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8899"
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:8899"
        assert "localhost" in env["NO_PROXY"]
        assert "127.0.0.1" in env["NO_PROXY"]
        # No provider is logged in, so no dummy vars should be set
        assert env.get("OPENAI_API_KEY") != "authsome-proxy-managed"

    def test_runner_injects_dummy_credentials_for_connected_providers(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        # Login to openai so it has a stored connection
        with patch("authsome.flows.bridge.secure_input_bridge", return_value={"api_key": "sk-real"}):
            client.login("openai", force=True)

        runner = ProxyRunner(client)

        with patch("authsome.proxy.runner.subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", Mock())):
                runner.run(["python", "-c", "print('ok')"])

        env = run_mock.call_args.kwargs["env"]
        # Dummy value should be present so the SDK initialises
        assert env["OPENAI_API_KEY"] == "authsome-proxy-managed"
        # But the real secret must NOT be in the env
        assert "sk-real" not in env.values()

    def test_runner_stops_proxy_on_subprocess_failure(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        runner = ProxyRunner(client)
        server = Mock()

        with patch("authsome.proxy.runner.subprocess.run", side_effect=RuntimeError("boom")):
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", server)):
                with pytest.raises(RuntimeError, match="boom"):
                    runner.run(["python", "-c", "print('ok')"])

        server.shutdown.assert_called_once()

    def test_runner_merges_existing_no_proxy(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        result = ProxyRunner._merge_no_proxy("internal.corp.com,10.0.0.1")
        assert "internal.corp.com" in result
        assert "10.0.0.1" in result
        assert "127.0.0.1" in result
        assert "localhost" in result


# ── Provider metadata tests ─────────────────────────────────────────────


class TestProviderProxyMetadata:
    """Bundled provider definitions include host_url for proxy routing."""

    def test_openai_provider_has_host_url(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        provider = client.get_provider("openai")

        assert provider.host_url == "api.openai.com"

    def test_github_provider_has_host_url(self, tmp_path: Path) -> None:
        client = AuthClient(home=tmp_path / ".authsome")
        client.init()

        provider = client.get_provider("github")

        assert provider.host_url == "api.github.com"


# ── CLI tests ────────────────────────────────────────────────────────────


class TestProxyCLI:
    """CLI integration for ``authsome proxy run``."""

    def test_run_requires_command(self) -> None:
        from click.testing import CliRunner

        from authsome.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

        assert result.exit_code != 0

    def test_run_invokes_runner(self, tmp_path: Path) -> None:
        """Verify the CLI path reaches ProxyRunner.run()."""
        from click.testing import CliRunner

        from authsome.cli import cli

        with patch("authsome.proxy.runner.ProxyRunner.run") as run_mock:
            run_mock.return_value = Mock(returncode=0)
            with patch("authsome.proxy.runner.ProxyRunner.__init__", return_value=None):
                runner = CliRunner()
                _result = runner.invoke(cli, ["run", "--", "echo", "hello"])

        # Should attempt to run
        run_mock.assert_called_once()


# ── Documentation tests ──────────────────────────────────────────────────


class TestDocumentation:
    """Verify that docs mention the proxy run command."""

    def test_readme_mentions_run_command(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "authsome run --" in readme

    def test_cli_docs_mentions_run_command(self) -> None:
        cli_docs = Path("docs/cli.md").read_text(encoding="utf-8")
        assert "authsome run --" in cli_docs
