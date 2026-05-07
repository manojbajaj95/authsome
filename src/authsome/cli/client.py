"""Internal HTTP client used by the CLI and local proxy runner."""

from __future__ import annotations

from typing import Any

import requests

DEFAULT_DAEMON_URL = "http://127.0.0.1:7998"


def raise_for_error(response: requests.Response) -> None:
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        try:
            data = response.json()
            error_name = data.get("error")
            if error_name:
                import authsome.errors as err_mod

                exc_cls = getattr(err_mod, error_name, None)
                if exc_cls and issubclass(exc_cls, err_mod.AuthsomeError):
                    provider = data.get("provider")
                    operation = data.get("operation")
                    message = data.get("message", "")

                    prefix = f"{error_name}: "
                    if message.startswith(prefix):
                        message = message[len(prefix) :]

                    suffix_part = "DO NOT HALLUCINATE"
                    if suffix_part in message:
                        message = message.split(suffix_part)[0].strip()
                        message = message.rstrip(". ")

                    if error_name == "ConnectionNotFoundError":
                        raise exc_cls(
                            provider=provider or "unknown",
                            connection=data.get("connection", "default"),
                            profile=data.get("profile", "default"),
                        ) from exc
                    elif error_name in ("ProviderNotFoundError", "ProfileNotFoundError"):
                        raise exc_cls(provider or "unknown") from exc
                    elif error_name == "UnsupportedAuthTypeError":
                        raise exc_cls(data.get("auth_type", "unknown"), provider=provider) from exc
                    elif error_name == "UnsupportedFlowError":
                        raise exc_cls(data.get("flow", "unknown"), provider=provider) from exc
                    elif error_name == "CredentialMissingError":
                        raise exc_cls(message, provider=provider) from exc
                    elif error_name == "InputCancelledError":
                        raise exc_cls(message) from exc
                    elif error_name == "TokenExpiredError":
                        raise exc_cls(provider=provider) from exc
                    elif error_name in ("RefreshFailedError", "AuthenticationFailedError", "DiscoveryError"):
                        reason = message
                        for prefix_to_strip in (f"[{provider}] ", f"({operation}) "):
                            if reason.startswith(prefix_to_strip):
                                reason = reason[len(prefix_to_strip) :]
                        raise exc_cls(reason, provider=provider) from exc
                    elif error_name == "InvalidProviderSchemaError":
                        raise exc_cls(message, provider=provider) from exc
                    elif error_name in ("EncryptionUnavailableError", "StoreUnavailableError"):
                        raise exc_cls(message) from exc
                    else:
                        raise err_mod.AuthsomeError(message, provider=provider, operation=operation) from exc
        except Exception:
            pass
        raise exc


class AuthsomeApiClient:
    """Small typed wrapper around the local daemon API."""

    def __init__(self, base_url: str = DEFAULT_DAEMON_URL) -> None:
        self._base_url = base_url.rstrip("/")

    def _get(self, path: str) -> dict[str, Any]:
        response = requests.get(f"{self._base_url}{path}", timeout=10)
        raise_for_error(response)
        return response.json()

    def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        response = requests.post(f"{self._base_url}{path}", json=body or {}, timeout=30)
        raise_for_error(response)
        return response.json()

    def _delete(self, path: str) -> dict[str, Any]:
        response = requests.delete(f"{self._base_url}{path}", timeout=30)
        raise_for_error(response)
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
