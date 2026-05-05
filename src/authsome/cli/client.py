"""Internal HTTP client used by the CLI and local proxy runner."""

from __future__ import annotations

from typing import Any

import requests

DEFAULT_DAEMON_URL = "http://127.0.0.1:7998"


class AuthsomeApiClient:
    """Small typed wrapper around the local daemon API."""

    def __init__(self, base_url: str = DEFAULT_DAEMON_URL) -> None:
        self._base_url = base_url.rstrip("/")

    def _get(self, path: str) -> dict[str, Any]:
        response = requests.get(f"{self._base_url}{path}", timeout=10)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        response = requests.post(f"{self._base_url}{path}", json=body or {}, timeout=30)
        response.raise_for_status()
        return response.json()

    def _delete(self, path: str) -> dict[str, Any]:
        response = requests.delete(f"{self._base_url}{path}", timeout=30)
        response.raise_for_status()
        return response.json()

    def health(self) -> dict[str, Any]:
        return self._get("/health")

    def ready(self) -> dict[str, Any]:
        return self._get("/ready")

    def start_login(self, **kwargs: Any) -> dict[str, Any]:
        return self._post("/auth/sessions", kwargs)

    def get_session(self, session_id: str) -> dict[str, Any]:
        return self._get(f"/auth/sessions/{session_id}")

    def resume_login_session(self, session_id: str, **kwargs: Any) -> dict[str, Any]:
        return self._post(f"/auth/sessions/{session_id}/resume", {"data": kwargs})

    def list_connections(self) -> dict[str, Any]:
        return self._get("/connections")

    def get_connection(self, provider: str, connection_name: str = "default") -> dict[str, Any]:
        return self._get(f"/connections/{provider}/{connection_name}")

    def logout(self, provider: str, connection_name: str = "default") -> None:
        self._post(f"/connections/{provider}/{connection_name}/logout")

    def revoke(self, provider: str) -> None:
        self._post(f"/connections/{provider}/revoke")

    def set_default_connection(self, provider: str, connection_name: str) -> None:
        self._post(f"/connections/{provider}/{connection_name}/default")

    def get_provider(self, provider: str) -> dict[str, Any]:
        return self._get(f"/providers/{provider}")

    def register_provider(self, definition_dict: dict[str, Any], force: bool = False) -> None:
        self._post("/providers", {"definition": definition_dict, "force": force})

    def remove(self, provider: str) -> None:
        self._delete(f"/providers/{provider}")

    def export(self, provider: str | None = None, connection_name: str = "default", format: str = "env") -> str:
        result = self._post(
            "/credentials/export",
            {"provider": provider, "connection": connection_name, "format": format},
        )
        return result["output"]

    def proxy_routes(self) -> dict[str, Any]:
        return self._get("/proxy/routes")

    def resolve_credentials(self, **kwargs: Any) -> dict[str, Any]:
        return self._post("/credentials/resolve", kwargs)

    def whoami(self) -> dict[str, Any]:
        return self._get("/whoami")

    def doctor(self) -> dict[str, Any]:
        return self.ready()
