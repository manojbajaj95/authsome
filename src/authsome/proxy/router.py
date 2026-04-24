"""Request router for outbound HTTP(S) traffic matching.

Matches requests to known providers using their ``host_url`` field,
excluding loopback addresses and OAuth authorization/token endpoints.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from urllib.parse import urlparse

from authsome.client import AuthClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RouteMatch:
    """Result of a successful route resolution."""

    provider: str
    connection: str = "default"


class RequestRouter:
    """Decide whether an outbound request maps to a connected Authsome provider."""

    _LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

    def __init__(self, client: AuthClient) -> None:
        self._client = client

    def route(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
    ) -> RouteMatch | None:
        """Return a :class:`RouteMatch` when exactly one provider matches.

        Returns ``None`` for loopback targets, auth endpoints, zero matches,
        or ambiguous (multiple) matches.
        """
        if host in self._LOOPBACK_HOSTS:
            return None

        matches: list[str] = []
        for provider in self._client.list_providers():
            if not provider.host_url:
                continue
            if self._is_auth_endpoint(provider, host, path):
                continue
            provider_host = self._extract_host(provider.host_url)
            if provider_host == host:
                # Only match providers that actually have a stored connection
                try:
                    self._client.get_connection(provider.name, "default")
                except Exception:
                    continue
                matches.append(provider.name)

        if len(matches) == 0:
            return None
        if len(matches) > 1:
            logger.warning(
                "Ambiguous proxy match for %s://%s:%s%s — matched providers: %s. Forwarding unchanged.",
                scheme,
                host,
                port,
                path,
                ", ".join(matches),
            )
            return None
        return RouteMatch(provider=matches[0], connection="default")

    @staticmethod
    def _is_auth_endpoint(provider, host: str, path: str) -> bool:
        """Return True if ``host + path`` is an OAuth authorization or token endpoint."""
        if not provider.oauth:
            return False

        urls = [
            provider.oauth.authorization_url,
            provider.oauth.token_url,
            provider.oauth.revocation_url,
            provider.oauth.device_authorization_url,
        ]
        for raw_url in urls:
            if not raw_url:
                continue
            parsed = urlparse(raw_url)
            if parsed.hostname == host and parsed.path == path:
                return True
        return False

    @staticmethod
    def _extract_host(host_url: str) -> str:
        """Extract the hostname from a ``host_url`` value.

        Handles both bare hostnames (``api.openai.com``) and full URLs
        (``https://api.openai.com``).
        """
        if "://" in host_url:
            return urlparse(host_url).hostname or host_url
        return host_url
