"""Mitmproxy addon and server lifecycle for header injection."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger
from mitmproxy import ctx as mitmproxy_ctx
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from authsome.auth import AuthLayer
from authsome.proxy.router import RouteMatch
from authsome.utils import utc_now

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_HEADER_REFRESH_WINDOW = timedelta(seconds=300)
_REGEX_HOST_PREFIX = "regex:"
_HOST_SPECIFICITY_REGEX = 0
_HOST_SPECIFICITY_EXACT = 1


@dataclass(frozen=True)
class _RouteTarget:
    match: RouteMatch
    path_prefix: str | None
    auth_endpoint_paths: frozenset[str]
    host_specificity: int


@dataclass(frozen=True)
class _RegexRouteTarget:
    host_pattern: re.Pattern[str]
    target: _RouteTarget


@dataclass(frozen=True)
class _HeaderCacheEntry:
    headers: dict[str, str]
    expires_at: datetime | None


class ProxyRouter:
    """Cached provider route table for proxy request matching."""

    def __init__(self, auth: AuthLayer) -> None:
        self._routes_by_host, self._regex_routes = self._build_routes(auth)

    def route(self, scheme: str, host: str, port: int, path: str) -> RouteMatch | None:
        """Return a route for a request, or None when the request should pass through."""
        if scheme.lower() != "https":
            return None

        normalized_host = _normalize_host(host)
        if normalized_host in _LOOPBACK_HOSTS:
            return None

        request_path = _request_path(path)
        candidate_targets = list(self._routes_by_host.get(normalized_host, ()))
        candidate_targets.extend(
            route.target for route in self._regex_routes if route.host_pattern.fullmatch(normalized_host)
        )

        matching_targets = [
            target
            for target in candidate_targets
            if _path_matches_prefix(request_path, target.path_prefix) and request_path not in target.auth_endpoint_paths
        ]

        if len(matching_targets) == 0:
            return None

        best_specificity = max(_target_specificity(target) for target in matching_targets)
        best_targets = [target for target in matching_targets if _target_specificity(target) == best_specificity]

        if len(best_targets) > 1:
            logger.warning(
                "Ambiguous proxy match for https://{}:{}{} — matched connections: {}. Forwarding unchanged.",
                normalized_host,
                port,
                path,
                ", ".join(f"{target.match.provider}/{target.match.connection}" for target in best_targets),
            )
            return None
        return best_targets[0].match

    @staticmethod
    def _build_routes(auth: AuthLayer) -> tuple[dict[str, tuple[_RouteTarget, ...]], tuple[_RegexRouteTarget, ...]]:
        routes_by_host: dict[str, list[_RouteTarget]] = {}
        regex_routes: list[_RegexRouteTarget] = []

        for provider_group in auth.list_connections():
            provider_name = provider_group["name"]
            selected_connections = [
                conn for conn in provider_group["connections"] if conn["connection_name"] == "default"
            ]

            try:
                definition = auth.get_provider(provider_name)
            except Exception as exc:
                logger.warning("Skipping proxy routes for provider {}: {}", provider_name, exc)
                continue

            for conn in selected_connections:
                target_host_url = conn.get("host_url")
                if not target_host_url:
                    continue

                resolved = definition.resolve_urls(conn.get("base_url"))
                route_match = RouteMatch(provider=provider_name, connection=conn["connection_name"])
                regex_pattern = _compile_host_regex(target_host_url)
                if regex_pattern is not None:
                    regex_routes.append(
                        _RegexRouteTarget(
                            host_pattern=regex_pattern,
                            target=_RouteTarget(
                                match=route_match,
                                path_prefix=None,
                                auth_endpoint_paths=_auth_endpoint_paths_for_regex(resolved, regex_pattern),
                                host_specificity=_HOST_SPECIFICITY_REGEX,
                            ),
                        )
                    )
                    continue

                host, path_prefix = _parse_host_url(target_host_url)
                if not host or host in _LOOPBACK_HOSTS:
                    continue

                auth_endpoint_paths = _auth_endpoint_paths(resolved, host)
                routes_by_host.setdefault(host, []).append(
                    _RouteTarget(
                        match=route_match,
                        path_prefix=path_prefix,
                        auth_endpoint_paths=auth_endpoint_paths,
                        host_specificity=_HOST_SPECIFICITY_EXACT,
                    )
                )

        return {host: tuple(routes) for host, routes in routes_by_host.items()}, tuple(regex_routes)


def _route(auth: AuthLayer, scheme: str, host: str, port: int, path: str) -> RouteMatch | None:
    """Return a RouteMatch when exactly one connected provider matches the request.

    Returns None for loopback targets, OAuth endpoints, zero matches, or ambiguous matches.
    """
    return ProxyRouter(auth).route(scheme, host, port, path)


def _is_auth_endpoint(provider, host: str, path: str) -> bool:
    return _request_path(path) in _auth_endpoint_paths(provider, _normalize_host(host))


def _extract_host(host_url: str) -> str:
    return _parse_host_url(host_url)[0]


def _parse_host_url(host_url: str) -> tuple[str, str | None]:
    raw = host_url.strip()
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    host = _normalize_host(parsed.hostname or raw)
    return host, _normalize_path_prefix(parsed.path)


def _compile_host_regex(host_url: str) -> re.Pattern[str] | None:
    raw = host_url.strip()
    if not raw.lower().startswith(_REGEX_HOST_PREFIX):
        return None

    pattern = raw[len(_REGEX_HOST_PREFIX) :].strip()
    if not pattern:
        logger.warning("Skipping empty regex host_url")
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        logger.warning("Skipping invalid regex host_url {}: {}", pattern, exc)
        return None


def _normalize_host(host: str) -> str:
    return host.strip().strip("[]").lower()


def _request_path(path: str) -> str:
    return urlparse(path).path or "/"


def _normalize_path_prefix(path: str | None) -> str | None:
    if not path or path == "/":
        return None
    return path.rstrip("/")


def _path_matches_prefix(request_path: str, path_prefix: str | None) -> bool:
    if path_prefix is None:
        return True
    return request_path == path_prefix or request_path.startswith(f"{path_prefix}/")


def _path_prefix_specificity(path_prefix: str | None) -> int:
    return len(path_prefix or "")


def _target_specificity(target: _RouteTarget) -> tuple[int, int]:
    return _path_prefix_specificity(target.path_prefix), target.host_specificity


def _auth_endpoint_paths(provider, host: str) -> frozenset[str]:
    if not provider.oauth:
        return frozenset()

    paths: set[str] = set()
    for raw_url in [
        provider.oauth.authorization_url,
        provider.oauth.token_url,
        provider.oauth.revocation_url,
        provider.oauth.device_authorization_url,
    ]:
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        if parsed.hostname and _normalize_host(parsed.hostname) == host:
            paths.add(parsed.path or "/")
    return frozenset(paths)


def _auth_endpoint_paths_for_regex(provider, host_pattern: re.Pattern[str]) -> frozenset[str]:
    if not provider.oauth:
        return frozenset()

    paths: set[str] = set()
    for raw_url in [
        provider.oauth.authorization_url,
        provider.oauth.token_url,
        provider.oauth.revocation_url,
        provider.oauth.device_authorization_url,
    ]:
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        if parsed.hostname and host_pattern.fullmatch(_normalize_host(parsed.hostname)):
            paths.add(parsed.path or "/")
    return frozenset(paths)


class AuthProxyAddon:
    """Mitmproxy addon that injects auth headers for matched requests."""

    def __init__(self, auth: AuthLayer) -> None:
        self._auth = auth
        self._router = ProxyRouter(auth)
        self._header_cache: dict[tuple[str, str], _HeaderCacheEntry] = {}
        self._header_locks: dict[tuple[str, str], threading.Lock] = {}

    def request(self, flow: http.HTTPFlow) -> None:
        match = self._router.route(flow.request.scheme, flow.request.host, flow.request.port, flow.request.path)
        if match is None:
            return

        try:
            headers = self._get_auth_headers(match)
        except Exception:
            logger.warning(
                "Failed to retrieve auth headers for provider={} connection={}. Forwarding unchanged.",
                match.provider,
                match.connection,
            )
            return

        for key, value in headers.items():
            flow.request.headers[key] = value

    def _get_auth_headers(self, match: RouteMatch) -> dict[str, str]:
        cache_key = (match.provider, match.connection)
        now = utc_now()
        cached = self._header_cache.get(cache_key)
        if cached and _header_cache_valid(cached, now):
            return cached.headers.copy()

        lock = self._header_locks.setdefault(cache_key, threading.Lock())
        with lock:
            now = utc_now()
            cached = self._header_cache.get(cache_key)
            if cached and _header_cache_valid(cached, now):
                return cached.headers.copy()

            headers = self._auth.get_auth_headers(match.provider, match.connection)
            record = self._auth.get_connection(match.provider, match.connection)
            self._header_cache[cache_key] = _HeaderCacheEntry(
                headers=headers.copy(),
                expires_at=record.expires_at,
            )
            return headers


def _header_cache_valid(entry: _HeaderCacheEntry, now: datetime) -> bool:
    if entry.expires_at is None:
        return True
    return now < entry.expires_at - _HEADER_REFRESH_WINDOW


class RunningProxy:
    """Handle for a proxy running in a background thread."""

    def __init__(self, url: str, master: DumpMaster, thread: threading.Thread, confdir: Path) -> None:
        self.url = url
        self.master = master
        self.thread = thread
        self.confdir = confdir

    @property
    def ca_cert_path(self) -> Path:
        """Path to the mitmproxy CA certificate (PEM format)."""
        return self.confdir / "mitmproxy-ca-cert.pem"

    def shutdown(self) -> None:
        self.master.shutdown()
        self.thread.join(timeout=5)


class _ProxyReadyAddon:
    def __init__(self, ready: threading.Event, state: dict, host: str, port: int) -> None:
        self._ready = ready
        self._state = state
        self._host = host
        self._port = port

    def running(self) -> None:
        bound_host, bound_port = _resolve_listen_address(self._host, self._port)
        self._state["url"] = f"http://{_format_proxy_url_host(bound_host)}:{bound_port}"
        self._ready.set()


def _resolve_listen_address(fallback_host: str, fallback_port: int) -> tuple[str, int]:
    master = getattr(mitmproxy_ctx, "master", None)
    proxyserver = master.addons.get("proxyserver") if master else None
    listen_addrs = proxyserver.listen_addrs() if proxyserver else []
    if not listen_addrs:
        return fallback_host, fallback_port

    host, port = listen_addrs[0]
    if host in {"", "0.0.0.0", "::"}:
        host = fallback_host or "127.0.0.1"
    return str(host), int(port)


def _format_proxy_url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _build_proxy_options(host: str, port: int, confdir: Path) -> Options:
    return Options(
        listen_host=host,
        listen_port=port,
        ssl_insecure=False,
        confdir=str(confdir),
    )


def start_proxy_server(
    auth: AuthLayer,
    host: str = "127.0.0.1",
    port: int = 0,
) -> RunningProxy:
    """Start a mitmproxy DumpMaster in a background thread."""
    import asyncio

    # Use the default mitmproxy confdir (~/.mitmproxy) for CA certificates
    confdir = Path.home() / ".mitmproxy"
    auth_addon = AuthProxyAddon(auth=auth)

    ready = threading.Event()
    state: dict = {}

    def _run() -> None:
        async def _async_main() -> None:
            opts = _build_proxy_options(host, port, confdir)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(auth_addon)
            master.addons.add(_ProxyReadyAddon(ready=ready, state=state, host=host, port=port))
            state["master"] = master
            await master.run()

        try:
            asyncio.run(_async_main())
        except Exception as exc:
            state["error"] = exc
            ready.set()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    if not ready.wait(timeout=10):
        raise RuntimeError("Proxy server failed to initialize within 10 s")
    if "error" in state:
        raise RuntimeError("Proxy server failed to initialize") from state["error"]
    if "master" not in state or "url" not in state:
        raise RuntimeError("Proxy server failed to publish its listen address")

    url = state["url"]
    logger.info("Proxy server listening on {}", url)
    return RunningProxy(url=url, master=state["master"], thread=thread, confdir=confdir)
