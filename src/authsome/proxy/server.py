"""Mitmproxy addon and server lifecycle for header injection."""

from __future__ import annotations

import threading
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger
from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from authsome.auth import AuthLayer
from authsome.proxy.router import RouteMatch

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _route(auth: AuthLayer, scheme: str, host: str, port: int, path: str) -> RouteMatch | None:
    """Return a RouteMatch when exactly one connected provider matches the request.

    Returns None for loopback targets, OAuth endpoints, zero matches, or ambiguous matches.
    """
    if host in _LOOPBACK_HOSTS:
        return None

    matches: list[str] = []
    # Check all active connections for host matches
    for p_group in auth.list_connections():
        p_name = p_group["name"]
        for conn in p_group["connections"]:
            if conn["connection_name"] != "default":
                continue

            # Connection record carries the resolved host_url
            target_host_url = conn.get("host_url")
            if not target_host_url:
                continue

            provider_host = _extract_host(target_host_url)
            if provider_host != host:
                continue

            # Still need definition to check if this is an auth endpoint
            try:
                definition = auth.get_provider(p_name)
                # Resolve templates in OAuth URLs before checking
                resolved = definition.resolve_urls(conn.get("base_url"))
                if _is_auth_endpoint(resolved, host, path):
                    continue
            except Exception:
                pass

            matches.append(p_name)

    if len(matches) == 0:
        return None
    if len(matches) > 1:
        logger.warning(
            "Ambiguous proxy match for {}://{}:{}{}  — matched providers: {}. Forwarding unchanged.",
            scheme,
            host,
            port,
            path,
            ", ".join(matches),
        )
        return None
    return RouteMatch(provider=matches[0], connection="default")


def _is_auth_endpoint(provider, host: str, path: str) -> bool:
    if not provider.oauth:
        return False
    for raw_url in [
        provider.oauth.authorization_url,
        provider.oauth.token_url,
        provider.oauth.revocation_url,
        provider.oauth.device_authorization_url,
    ]:
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        if parsed.hostname == host and parsed.path == path:
            return True
    return False


def _extract_host(host_url: str) -> str:
    if "://" in host_url:
        return urlparse(host_url).hostname or host_url
    return host_url


class AuthProxyAddon:
    """Mitmproxy addon that injects auth headers for matched requests."""

    def __init__(self, auth: AuthLayer) -> None:
        self._auth = auth

    def request(self, flow: http.HTTPFlow) -> None:
        match = _route(self._auth, flow.request.scheme, flow.request.host, flow.request.port, flow.request.path)
        if match is None:
            return

        try:
            headers = self._auth.get_auth_headers(match.provider, match.connection)
        except Exception:
            logger.warning(
                "Failed to retrieve auth headers for provider={} connection={}. Forwarding unchanged.",
                match.provider,
                match.connection,
            )
            return

        for key, value in headers.items():
            flow.request.headers[key] = value


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


def start_proxy_server(auth: AuthLayer, host: str = "127.0.0.1", port: int = 0) -> RunningProxy:
    """Start a mitmproxy DumpMaster in a background thread."""
    import asyncio

    from authsome.auth.flows.bridge import _find_free_port

    if port == 0:
        port = _find_free_port()

    # Use the default mitmproxy confdir (~/.mitmproxy) for CA certificates
    confdir = Path.home() / ".mitmproxy"

    ready = threading.Event()
    state: dict = {}

    def _run() -> None:
        async def _async_main() -> None:
            opts = Options(
                listen_host=host,
                listen_port=port,
                ssl_insecure=True,
                confdir=str(confdir),
            )
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(AuthProxyAddon(auth=auth))
            state["master"] = master
            ready.set()
            await master.run()

        asyncio.run(_async_main())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    if not ready.wait(timeout=10):
        raise RuntimeError("Proxy server failed to initialize within 10 s")

    url = f"http://{host}:{port}"
    logger.info("Proxy server listening on {}", url)
    return RunningProxy(url=url, master=state["master"], thread=thread, confdir=confdir)
