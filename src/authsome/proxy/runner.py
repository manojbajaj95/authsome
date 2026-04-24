"""Subprocess runner that launches commands behind the local auth proxy.

:class:`ProxyRunner` handles the full lifecycle:
1. Start the mitmproxy-backed proxy server.
2. Prepare child environment with ``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``NO_PROXY``.
3. Inject dummy credential env vars so SDKs initialise.
4. Run the subprocess.
5. Shut down the proxy on exit.
"""

from __future__ import annotations

import logging
import os
import subprocess

from authsome.client import AuthClient
from authsome.proxy.server import RunningProxy, start_proxy_server

logger = logging.getLogger(__name__)


class ProxyRunner:
    """Launch a subprocess behind the Authsome local auth proxy."""

    def __init__(self, client: AuthClient) -> None:
        self._client = client

    def run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run *command* behind the auth-injecting proxy.

        Returns the :class:`subprocess.CompletedProcess` from the child.
        The proxy is always shut down, even if the child crashes.
        """
        proxy_url, server = self._start_proxy()
        env = os.environ.copy()
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["NO_PROXY"] = self._merge_no_proxy(env.get("NO_PROXY", ""))

        # Set dummy env vars for connected providers so SDKs that require
        # e.g. OPENAI_API_KEY to be set will initialise and route through the proxy
        self._inject_dummy_credentials(env)

        try:
            return subprocess.run(
                command,
                env=env,
                capture_output=False,
                text=True,
                check=False,
            )
        finally:
            server.shutdown()

    def _start_proxy(self) -> tuple[str, RunningProxy]:
        """Start the proxy and return ``(proxy_url, server)``."""
        server = start_proxy_server(self._client)
        return server.url, server

    def _inject_dummy_credentials(self, env: dict[str, str]) -> None:
        """Set placeholder env vars for every connected provider with an export config.

        Many SDKs (e.g. the OpenAI Python client) refuse to start unless
        their expected env var (``OPENAI_API_KEY``) is set.  We inject a
        recognisable dummy value so the SDK initialises normally, then the
        proxy overwrites the ``Authorization`` header at request time with the
        real credential.
        """
        connected_names = {entry["name"] for entry in self._client.list_connections()}

        for provider in self._client.list_providers():
            if provider.name not in connected_names:
                continue
            if not provider.export or not provider.export.env:
                continue

            for env_var in provider.export.env.values():
                env[env_var] = "authsome-proxy-managed"
                logger.debug("Set dummy env var %s for provider %s", env_var, provider.name)

    @staticmethod
    def _merge_no_proxy(existing: str) -> str:
        """Merge ``127.0.0.1`` and ``localhost`` into an existing ``NO_PROXY`` value."""
        entries = [item for item in existing.split(",") if item]
        for host in ["127.0.0.1", "localhost"]:
            if host not in entries:
                entries.append(host)
        return ",".join(entries)
