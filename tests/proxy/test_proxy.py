"""Tests for the HTTP proxy injection feature."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from authsome.auth import AuthLayer
from authsome.auth.input_provider import MockInputProvider
from authsome.context import AuthsomeContext
from authsome.proxy.router import RouteMatch
from authsome.proxy.server import AuthProxyAddon, ProxyRouter, _build_proxy_options, _route


def _make_auth(tmp_path: Path) -> AuthLayer:
    home = tmp_path / ".authsome"
    actx = AuthsomeContext.create(home=home)
    return actx.auth


# ── Routing function tests ────────────────────────────────────────────────


class TestRouting:
    """_route() matching and rejection behaviour."""

    def test_matches_provider_host(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        auth.login("openai", force=True, input_provider=MockInputProvider({"api_key": "sk-test-padded-for-regex-12"}))

        match = _route(auth, "https", "api.openai.com", 443, "/v1/responses")

        assert match == RouteMatch(provider="openai", connection="default")

    def test_rejects_plain_http_provider_host(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        auth.login("openai", force=True, input_provider=MockInputProvider({"api_key": "sk-test-padded-for-regex-12"}))

        assert _route(auth, "http", "api.openai.com", 80, "/v1/responses") is None

    def test_ignores_named_connection_without_default(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        auth.login(
            "openai",
            connection_name="work",
            force=True,
            input_provider=MockInputProvider({"api_key": "sk-work-padded-for-regex-12"}),
        )

        match = _route(auth, "https", "api.openai.com", 443, "/v1/responses")

        assert match is None

    def test_routes_default_when_named_connection_also_exists(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        auth.login(
            "openai",
            force=True,
            input_provider=MockInputProvider({"api_key": "sk-default-padded-for-regex-12"}),
        )
        auth.login(
            "openai",
            connection_name="work",
            force=True,
            input_provider=MockInputProvider({"api_key": "sk-work-padded-for-regex-12"}),
        )

        match = _route(auth, "https", "api.openai.com", 443, "/v1/responses")

        assert match == RouteMatch(provider="openai", connection="default")

    def test_host_url_path_limits_routing(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "custom",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1",
                        "base_url": None,
                    }
                ],
            }
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.example.com", 443, "/v1/resources") == RouteMatch(
            provider="custom",
            connection="default",
        )
        assert router.route("https", "api.example.com", 443, "/v2/resources") is None

    def test_more_specific_host_url_path_wins_over_host_only_route(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "root",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "api.example.com",
                        "base_url": None,
                    }
                ],
            },
            {
                "name": "v1",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1",
                        "base_url": None,
                    }
                ],
            },
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.example.com", 443, "/v1/resources") == RouteMatch(
            provider="v1",
            connection="default",
        )
        assert router.route("https", "api.example.com", 443, "/v2/resources") == RouteMatch(
            provider="root",
            connection="default",
        )

    def test_more_specific_nested_host_url_path_wins(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "v1",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1",
                        "base_url": None,
                    }
                ],
            },
            {
                "name": "beta",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1/beta",
                        "base_url": None,
                    }
                ],
            },
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.example.com", 443, "/v1/beta/resources") == RouteMatch(
            provider="beta",
            connection="default",
        )
        assert router.route("https", "api.example.com", 443, "/v1/resources") == RouteMatch(
            provider="v1",
            connection="default",
        )

    def test_equal_specificity_host_url_paths_remain_ambiguous(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "first",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1",
                        "base_url": None,
                    }
                ],
            },
            {
                "name": "second",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "https://api.example.com/v1",
                        "base_url": None,
                    }
                ],
            },
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.example.com", 443, "/v1/resources") is None

    def test_regex_host_url_matches_multiple_hosts(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "github-shards",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": r"regex:^api[0-9]+\.github\.com$",
                        "base_url": None,
                    }
                ],
            }
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api1.github.com", 443, "/repos") == RouteMatch(
            provider="github-shards",
            connection="default",
        )
        assert router.route("https", "api2.github.com", 443, "/repos") == RouteMatch(
            provider="github-shards",
            connection="default",
        )
        assert router.route("https", "api.github.com", 443, "/repos") is None

    def test_exact_host_route_wins_over_regex_route(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "regex",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": r"regex:^api[0-9]+\.github\.com$",
                        "base_url": None,
                    }
                ],
            },
            {
                "name": "exact",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "api1.github.com",
                        "base_url": None,
                    }
                ],
            },
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api1.github.com", 443, "/repos") == RouteMatch(
            provider="exact",
            connection="default",
        )
        assert router.route("https", "api2.github.com", 443, "/repos") == RouteMatch(
            provider="regex",
            connection="default",
        )

    def test_plain_host_url_does_not_use_regex_matching(self) -> None:
        auth = Mock()
        provider = Mock()
        provider.oauth = None
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "plain",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "api.github.com",
                        "base_url": None,
                    }
                ],
            }
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.github.com", 443, "/repos") == RouteMatch(
            provider="plain",
            connection="default",
        )
        assert router.route("https", "apiXgithub.com", 443, "/repos") is None

    def test_rejects_loopback_host(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)

        assert _route(auth, "http", "127.0.0.1", 8080, "/anything") is None
        assert _route(auth, "http", "localhost", 8080, "/anything") is None
        assert _route(auth, "http", "::1", 8080, "/anything") is None

    def test_rejects_provider_token_endpoint(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)

        assert _route(auth, "https", "github.com", 443, "/login/oauth/access_token") is None

    def test_rejects_connected_provider_auth_endpoint_with_query(self) -> None:
        auth = Mock()
        oauth = Mock()
        oauth.authorization_url = "https://api.example.com/oauth/authorize"
        oauth.token_url = "https://api.example.com/oauth/token"
        oauth.revocation_url = None
        oauth.device_authorization_url = None
        provider = Mock()
        provider.oauth = oauth
        provider.resolve_urls.return_value = provider
        auth.get_provider.return_value = provider
        auth.list_connections.return_value = [
            {
                "name": "custom",
                "connections": [
                    {
                        "connection_name": "default",
                        "host_url": "api.example.com",
                        "base_url": None,
                    }
                ],
            }
        ]

        router = ProxyRouter(auth)

        assert router.route("https", "api.example.com", 443, "/oauth/token?grant_type=refresh_token") is None

    def test_no_match_for_unknown_host(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)

        assert _route(auth, "https", "unknown.example.com", 443, "/v1") is None

    def test_no_match_without_connection(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)

        assert _route(auth, "https", "api.openai.com", 443, "/v1/responses") is None


# ── Addon tests ──────────────────────────────────────────────────────────


class TestAuthProxyAddon:
    """AuthProxyAddon header injection and passthrough."""

    def _make_flow(self, scheme="https", host="api.openai.com", port=443, path="/v1/responses", headers=None):
        flow = Mock()
        flow.request.scheme = scheme
        flow.request.host = host
        flow.request.port = port
        flow.request.path = path
        flow.request.headers = headers if headers is not None else {}
        return flow

    def _make_addon(self, auth, match):
        router = Mock()
        router.route.return_value = match
        with patch("authsome.proxy.server.ProxyRouter", return_value=router):
            addon = AuthProxyAddon(auth=auth)
        return addon, router

    def test_addon_injects_headers_for_matched_request(self) -> None:
        auth = Mock()
        flow = self._make_flow()
        auth.get_auth_headers.return_value = {"Authorization": "Bearer sk-test"}
        auth.get_connection.return_value.expires_at = None

        addon, _router = self._make_addon(auth, RouteMatch(provider="openai", connection="default"))
        addon.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-test"

    def test_addon_overwrites_existing_authorization_header(self) -> None:
        auth = Mock()
        flow = self._make_flow(headers={"Authorization": "Bearer existing"})
        auth.get_auth_headers.return_value = {"Authorization": "Bearer sk-authsome"}
        auth.get_connection.return_value.expires_at = None

        addon, _router = self._make_addon(auth, RouteMatch(provider="openai", connection="default"))
        addon.request(flow)

        assert flow.request.headers["Authorization"] == "Bearer sk-authsome"

    def test_addon_skips_unmatched_request(self) -> None:
        auth = Mock()
        flow = self._make_flow(host="example.com", path="/")

        addon, _router = self._make_addon(auth, None)
        addon.request(flow)

        auth.get_auth_headers.assert_not_called()

    def test_addon_continues_on_header_retrieval_failure(self) -> None:
        auth = Mock()
        auth.get_auth_headers.side_effect = RuntimeError("token expired")
        flow = self._make_flow()

        addon, _router = self._make_addon(auth, RouteMatch(provider="openai", connection="default"))
        addon.request(flow)

        assert "Authorization" not in flow.request.headers

    def test_addon_caches_headers_for_connection(self) -> None:
        auth = Mock()
        auth.get_auth_headers.return_value = {"Authorization": "Bearer sk-test"}
        auth.get_connection.return_value.expires_at = None
        addon, _router = self._make_addon(auth, RouteMatch(provider="openai", connection="default"))

        addon.request(self._make_flow())
        addon.request(self._make_flow())

        auth.get_auth_headers.assert_called_once_with("openai", "default")


# ── Runner tests ─────────────────────────────────────────────────────────


class TestProxyRunner:
    """ProxyRunner subprocess environment and lifecycle."""

    def test_runner_sets_proxy_environment(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        auth = _make_auth(tmp_path)
        runner = ProxyRunner(auth)

        with patch("authsome.proxy.runner.subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", Mock())):
                with patch.object(runner, "_build_ca_bundle", return_value=Path("/tmp/fake-ca.pem")):
                    runner.run(["python", "-c", "print('ok')"])

        env = run_mock.call_args.kwargs["env"]
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8899"
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:8899"
        assert env["http_proxy"] == "http://127.0.0.1:8899"
        assert env["https_proxy"] == "http://127.0.0.1:8899"
        assert env["SSL_CERT_FILE"] == "/tmp/fake-ca.pem"
        assert "localhost" in env["NO_PROXY"]
        assert "127.0.0.1" in env["NO_PROXY"]
        assert "::1" in env["NO_PROXY"]
        assert env.get("OPENAI_API_KEY") != "authsome-proxy-managed"

    def test_runner_injects_dummy_credentials_for_connected_providers(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        auth = _make_auth(tmp_path)
        auth.login("openai", force=True, input_provider=MockInputProvider({"api_key": "sk-real-padded-for-regex-12"}))

        runner = ProxyRunner(auth)

        with patch("authsome.proxy.runner.subprocess.run") as run_mock:
            run_mock.return_value.returncode = 0
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", Mock())):
                with patch.object(runner, "_build_ca_bundle", return_value=None):
                    runner.run(["python", "-c", "print('ok')"])

        env = run_mock.call_args.kwargs["env"]
        assert env["OPENAI_API_KEY"] == "authsome-proxy-managed"
        assert "sk-real" not in env.values()

    def test_runner_stops_proxy_on_subprocess_failure(self, tmp_path: Path) -> None:
        from authsome.proxy.runner import ProxyRunner

        auth = _make_auth(tmp_path)
        runner = ProxyRunner(auth)
        server = Mock()

        with patch("authsome.proxy.runner.subprocess.run", side_effect=RuntimeError("boom")):
            with patch.object(runner, "_start_proxy", return_value=("http://127.0.0.1:8899", server)):
                with patch.object(runner, "_build_ca_bundle", return_value=None):
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
        assert "::1" in result


class TestProxyServer:
    """Proxy server options and lifecycle helpers."""

    def test_proxy_options_verify_upstream_tls(self, tmp_path: Path) -> None:
        opts = _build_proxy_options("127.0.0.1", 0, tmp_path)

        assert opts.ssl_insecure is False


# ── Provider metadata tests ─────────────────────────────────────────────


class TestProviderProxyMetadata:
    """Bundled provider definitions include host_url for proxy routing."""

    def test_openai_provider_has_host_url(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        provider = auth.get_provider("openai")
        assert provider.host_url == "api.openai.com"

    def test_github_provider_has_host_url(self, tmp_path: Path) -> None:
        auth = _make_auth(tmp_path)
        provider = auth.get_provider("github")
        assert provider.host_url == "api.github.com"


# ── CLI tests ────────────────────────────────────────────────────────────


class TestProxyCLI:
    """CLI integration for ``authsome run``."""

    def test_run_requires_command(self) -> None:
        from click.testing import CliRunner

        from authsome.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["run"])

        assert result.exit_code != 0

    def test_run_invokes_runner(self, tmp_path: Path) -> None:
        from click.testing import CliRunner

        from authsome.cli import cli

        with patch("authsome.proxy.runner.ProxyRunner.run") as run_mock:
            run_mock.return_value = Mock(returncode=0)
            with patch("authsome.proxy.runner.ProxyRunner.__init__", return_value=None):
                runner = CliRunner()
                _result = runner.invoke(cli, ["run", "--", "echo", "hello"])

        run_mock.assert_called_once()


# ── Documentation tests ──────────────────────────────────────────────────


class TestDocumentation:
    """Verify that docs mention the proxy run command."""

    def test_readme_mentions_run_command(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        assert "authsome run" in readme

    def test_cli_docs_mentions_run_command(self) -> None:
        cli_docs = Path("docs/cli.md").read_text(encoding="utf-8")
        assert "authsome run" in cli_docs
