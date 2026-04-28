"""Subprocess runner that launches commands behind the local auth proxy."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from loguru import logger

from authsome.auth import AuthLayer
from authsome.proxy.server import RunningProxy, start_proxy_server


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

        # Build a combined CA bundle so subprocesses trust the mitmproxy CA
        ca_bundle_path = self._build_ca_bundle(server)
        if ca_bundle_path:
            env["SSL_CERT_FILE"] = str(ca_bundle_path)
            env["REQUESTS_CA_BUNDLE"] = str(ca_bundle_path)
            env["CURL_CA_BUNDLE"] = str(ca_bundle_path)
            # NODE_EXTRA_CA_CERTS adds to (not replaces) Node's built-in CAs
            env["NODE_EXTRA_CA_CERTS"] = str(server.ca_cert_path)
            logger.debug("CA bundle injected: {}", ca_bundle_path)

        try:
            return subprocess.run(command, env=env, capture_output=False, text=True, check=False)
        finally:
            server.shutdown()
            # Clean up the temporary CA bundle
            if ca_bundle_path and ca_bundle_path.exists():
                try:
                    ca_bundle_path.unlink()
                except OSError:
                    pass

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
                logger.debug("Set dummy env var {} for provider {}", env_var, provider.name)

    @staticmethod
    def _build_ca_bundle(server: RunningProxy) -> Path | None:
        """Create a temp file containing system CAs + the mitmproxy CA cert."""
        mitm_ca = server.ca_cert_path
        if not mitm_ca.exists():
            logger.warning("Mitmproxy CA cert not found at {}; HTTPS may fail", mitm_ca)
            return None

        # Find the system CA bundle (certifi is a dependency of requests, so it's guaranteed)
        import certifi

        system_ca_path = Path(certifi.where())

        # Combine system CAs + mitmproxy CA into a temp file
        # We use a unique prefix to avoid collisions if multiple instances run
        fd, name = tempfile.mkstemp(prefix="authsome-ca-", suffix=".pem", text=True)
        os.close(fd)  # Close immediately, we'll use Path.write_text
        path = Path(name)
        try:
            content = system_ca_path.read_text(encoding="utf-8") + "\n" + mitm_ca.read_text(encoding="utf-8")
            path.write_text(content, encoding="utf-8")
        except Exception as e:
            logger.error("Failed to create combined CA bundle: {}", e)
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
            return None

        return path

    @staticmethod
    def _merge_no_proxy(existing: str) -> str:
        entries = [item for item in existing.split(",") if item]
        for host in ["127.0.0.1", "localhost"]:
            if host not in entries:
                entries.append(host)
        return ",".join(entries)
