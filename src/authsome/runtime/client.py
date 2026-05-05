"""Typed runtime client — stable API surface for CLI, proxy, and SDK consumers.

The client defines the contract for talking to the Auth runtime.  Two
concrete transports ship today:

- :class:`InProcessRuntimeClient` — calls :class:`RuntimeServer.handle_json`
  directly.  Used when CLI and server run in the same process.
- :class:`HttpRuntimeClient` — makes real HTTP requests to a remote URL.
  Used when the Auth runtime is deployed as a hosted service.

Both transports are drop-in replacements for each other.  The proxy and
CLI never know which transport is active.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from authsome.runtime.server import RuntimeServer


class RuntimeClient(ABC):
    """Abstract runtime client — the stable typed API surface.

    Every method returns a plain dict so that the transport layer
    (in-process or HTTP) is invisible to callers.
    """

    # ── Sessions ──────────────────────────────────────────────────────────

    @abstractmethod
    def start_login(self, **kwargs: Any) -> dict[str, Any]:
        """Create a new login session."""
        ...

    @abstractmethod
    def complete_login_session(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        """Execute the actual login flow and update session state."""
        ...

    @abstractmethod
    def get_session(self, session_id: str) -> dict[str, Any]:
        """Return session status by ID."""
        ...

    @abstractmethod
    def list_sessions(self) -> dict[str, Any]:
        """Return all active sessions."""
        ...

    # ── Connections ───────────────────────────────────────────────────────

    @abstractmethod
    def list_connections(self) -> dict[str, Any]:
        """Return connections and provider metadata."""
        ...

    # ── Credential resolution ─────────────────────────────────────────────

    @abstractmethod
    def resolve_credentials(self, **kwargs: Any) -> dict[str, Any]:
        """Resolve auth headers for a provider connection."""
        ...

    # ── CLI Operations ────────────────────────────────────────────────────

    @abstractmethod
    def logout(self, provider: str, connection_name: str = "default") -> None:
        """Logout of a provider connection."""
        ...

    @abstractmethod
    def revoke(self, provider: str, connection_name: str = "default") -> None:
        """Revoke a provider connection."""
        ...

    @abstractmethod
    def remove(self, provider: str) -> None:
        """Remove a custom provider."""
        ...

    @abstractmethod
    def get_connection(self, provider: str, connection_name: str = "default") -> dict[str, Any]:
        """Get connection details."""
        ...

    @abstractmethod
    def get_provider(self, provider: str) -> dict[str, Any]:
        """Get provider details."""
        ...

    @abstractmethod
    def register_provider(self, definition_dict: dict[str, Any], force: bool = False) -> None:
        """Register a new provider definition."""
        ...

    @abstractmethod
    def export(self, provider: str | None = None, connection_name: str = "default", format: str = "env") -> str:
        """Export credentials."""
        ...

    @abstractmethod
    def whoami(self) -> dict[str, Any]:
        """Get current profile and connection status."""
        ...

    @abstractmethod
    def doctor(self) -> dict[str, Any]:
        """Run diagnostics and return results."""
        ...


class InProcessRuntimeClient(RuntimeClient):
    """In-process transport — calls RuntimeServer.handle_json() directly.

    This is the default for local CLI usage where everything runs in a
    single process.
    """

    def __init__(self, server: RuntimeServer) -> None:
        self._server = server

    def start_login(self, **kwargs: Any) -> dict[str, Any]:
        return self._server.handle_json("POST", "/v1/sessions", kwargs)

    def get_session(self, session_id: str) -> dict[str, Any]:
        return self._server.handle_json("GET", f"/v1/sessions/{session_id}")

    def complete_login_session(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        return self._server.handle_json("POST", f"/v1/sessions/{session_id}/complete", kwargs)

    def list_sessions(self) -> dict[str, Any]:
        return self._server.handle_json("GET", "/v1/sessions")

    def list_connections(self) -> dict[str, Any]:
        return self._server.handle_json("GET", "/v1/connections")

    def resolve_credentials(self, **kwargs: Any) -> dict[str, Any]:
        return self._server.handle_json("POST", "/v1/credentials/resolve", kwargs)

    def logout(self, provider: str, connection_name: str = "default") -> None:
        self._server.handle_json("POST", f"/v1/connections/{provider}/{connection_name}/logout")

    def revoke(self, provider: str, connection_name: str = "default") -> None:
        self._server.handle_json("POST", f"/v1/connections/{provider}/{connection_name}/revoke")

    def remove(self, provider: str) -> None:
        self._server.handle_json("DELETE", f"/v1/providers/{provider}")

    def get_connection(self, provider: str, connection_name: str = "default") -> dict[str, Any]:
        return self._server.handle_json("GET", f"/v1/connections/{provider}/{connection_name}")

    def get_provider(self, provider: str) -> dict[str, Any]:
        return self._server.handle_json("GET", f"/v1/providers/{provider}")

    def register_provider(self, definition_dict: dict[str, Any], force: bool = False) -> None:
        self._server.handle_json("POST", "/v1/providers", {"definition": definition_dict, "force": force})

    def export(self, provider: str | None = None, connection_name: str = "default", format: str = "env") -> str:
        res = self._server.handle_json(
            "POST",
            "/v1/connections/export",
            {"provider": provider, "connection_name": connection_name, "format": format},
        )
        return res["output"]

    def whoami(self) -> dict[str, Any]:
        return self._server.handle_json("GET", "/v1/whoami")

    def doctor(self) -> dict[str, Any]:
        return self._server.handle_json("GET", "/v1/doctor")


class HttpRuntimeClient(RuntimeClient):
    """HTTP transport — calls a remote Auth runtime server over HTTPS.

    Used when the Auth runtime is deployed as a hosted service.  The
    CLI and proxy talk to the remote server exactly like they would
    talk to an in-process server.
    """

    def __init__(self, base_url: str, auth_token: str | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return headers

    def _get(self, path: str) -> dict[str, Any]:
        import requests

        response = requests.get(
            f"{self._base_url}{path}",
            headers=self._headers(),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        import requests

        response = requests.post(
            f"{self._base_url}{path}",
            json=body or {},
            headers=self._headers(),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def start_login(self, **kwargs: Any) -> dict[str, Any]:
        return self._post("/v1/sessions", kwargs)

    def get_session(self, session_id: str) -> dict[str, Any]:
        return self._get(f"/v1/sessions/{session_id}")

    def complete_login_session(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        return self._post(f"/v1/sessions/{session_id}/complete", kwargs)

    def list_sessions(self) -> dict[str, Any]:
        return self._get("/v1/sessions")

    def list_connections(self) -> dict[str, Any]:
        return self._get("/v1/connections")

    def whoami(self) -> dict[str, Any]:
        return self._get("/v1/whoami")

    def doctor(self) -> dict[str, Any]:
        return self._get("/v1/doctor")

    def resolve_credentials(self, **kwargs: Any) -> dict[str, Any]:
        return self._post("/v1/credentials/resolve", kwargs)

    def _delete(self, path: str) -> dict[str, Any]:
        import requests

        response = requests.delete(
            f"{self._base_url}{path}",
            headers=self._headers(),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def logout(self, provider: str, connection_name: str = "default") -> None:
        self._post(f"/v1/connections/{provider}/{connection_name}/logout")

    def revoke(self, provider: str, connection_name: str = "default") -> None:
        self._post(f"/v1/connections/{provider}/{connection_name}/revoke")

    def remove(self, provider: str) -> None:
        self._delete(f"/v1/providers/{provider}")

    def get_connection(self, provider: str, connection_name: str = "default") -> dict[str, Any]:
        return self._get(f"/v1/connections/{provider}/{connection_name}")

    def get_provider(self, provider: str) -> dict[str, Any]:
        return self._get(f"/v1/providers/{provider}")

    def register_provider(self, definition_dict: dict[str, Any], force: bool = False) -> None:
        self._post("/v1/providers", {"definition": definition_dict, "force": force})

    def export(self, provider: str | None = None, connection_name: str = "default", format: str = "env") -> str:
        res = self._post(
            "/v1/connections/export",
            {"provider": provider, "connection_name": connection_name, "format": format},
        )
        return res["output"]
