"""Subprocess runner that launches commands behind the local auth proxy."""

from __future__ import annotations

import logging
import os
import subprocess

from authsome.auth import AuthLayer
from authsome.proxy.server import RunningProxy, start_proxy_server

logger = logging.getLogger(__name__)


class ProxyRunner:
    """Launch a subprocess behind the Authsome local auth proxy."""

    def __init__(self, auth: AuthLayer) -> None:
        self._auth = auth

    def run(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run *command* behind the auth-injecting proxy."""
        proxy_url, server = self._start_proxy()
        env = os.environ.copy()
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["NO_PROXY"] = self._merge_no_proxy(env.get("NO_PROXY", ""))
        env["AUTHSOME_PROXY_MODE"] = "true"

        # Set dummy env vars for connected providers so SDKs that require
        # e.g. OPENAI_API_KEY to be set will initialise and route through the proxy
        self._inject_dummy_credentials(env)

        try:
            return subprocess.run(command, env=env, capture_output=False, text=True, check=False)
        finally:
            server.shutdown()

    def _start_proxy(self) -> tuple[str, RunningProxy]:
        server = start_proxy_server(self._auth)
        return server.url, server

    def _inject_dummy_credentials(self, env: dict[str, str]) -> None:
        connected_names = {entry["name"] for entry in self._auth.list_connections()}
        for provider in self._auth.list_providers():
            if provider.name not in connected_names:
                continue
            if not provider.export or not provider.export.env:
                continue
            for env_var in provider.export.env.values():
                env[env_var] = "authsome-proxy-managed"
                logger.debug("Set dummy env var %s for provider %s", env_var, provider.name)

    @staticmethod
    def _merge_no_proxy(existing: str) -> str:
        entries = [item for item in existing.split(",") if item]
        for host in ["127.0.0.1", "localhost"]:
            if host not in entries:
                entries.append(host)
        return ",".join(entries)
