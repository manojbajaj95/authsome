"""Mitmproxy addon and server lifecycle for header injection.

:class:`AuthProxyAddon` is a mitmproxy addon that intercepts outgoing requests,
routes them through :class:`RequestRouter`, and injects provider auth headers
via :meth:`AuthClient.get_auth_headers`.

:func:`start_proxy_server` spins up a short-lived ``DumpMaster`` suitable for a
single ``authsome proxy run`` invocation.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from mitmproxy import http
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from authsome.client import AuthClient
from authsome.proxy.router import RequestRouter

logger = logging.getLogger(__name__)


@dataclass
class AuthProxyAddon:
    """Mitmproxy addon that injects auth headers for matched requests."""

    client: AuthClient
    router: RequestRouter

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept outgoing requests and inject auth headers when matched."""
        match = self.router.route(
            flow.request.scheme,
            flow.request.host,
            flow.request.port,
            flow.request.path,
        )
        if match is None:
            return

        try:
            headers = self.client.get_auth_headers(match.provider, match.connection)
        except Exception:
            logger.warning(
                "Failed to retrieve auth headers for provider=%s connection=%s. Forwarding unchanged.",
                match.provider,
                match.connection,
            )
            return

        # Always overwrite — authsome is the source of truth for credentials
        for key, value in headers.items():
            flow.request.headers[key] = value


def build_addon(client: AuthClient) -> AuthProxyAddon:
    """Create an :class:`AuthProxyAddon` wired to *client*."""
    return AuthProxyAddon(client=client, router=RequestRouter(client))


class RunningProxy:
    """Handle for a proxy that is running in a background thread."""

    def __init__(self, url: str, master: DumpMaster, thread: threading.Thread) -> None:
        self.url = url
        self.master = master
        self.thread = thread

    def shutdown(self) -> None:
        self.master.shutdown()
        self.thread.join(timeout=5)


def start_proxy_server(
    client: AuthClient,
    host: str = "127.0.0.1",
    port: int = 0,
) -> RunningProxy:
    """Start a mitmproxy ``DumpMaster`` in a background thread.

    Returns a :class:`RunningProxy` whose ``.url`` attribute contains the
    ``http://host:port`` base URL suitable for ``HTTP_PROXY`` / ``HTTPS_PROXY``.

    ``DumpMaster`` must be created inside an async context because its
    ``__init__`` references the running event loop.  We create it inside
    ``asyncio.run()`` in the background thread and use a
    :class:`threading.Event` to hand the master reference back.
    """
    import asyncio

    from authsome.flows.bridge import _find_free_port

    if port == 0:
        port = _find_free_port()

    ready = threading.Event()
    state: dict = {}

    def _run() -> None:
        async def _async_main() -> None:
            opts = Options(listen_host=host, listen_port=port, ssl_insecure=True)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(build_addon(client))
            state["master"] = master
            ready.set()
            await master.run()

        asyncio.run(_async_main())

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    if not ready.wait(timeout=10):
        raise RuntimeError("Proxy server failed to initialize within 10 s")

    url = f"http://{host}:{port}"
    logger.info("Proxy server listening on %s", url)
    return RunningProxy(url=url, master=state["master"], thread=thread)
