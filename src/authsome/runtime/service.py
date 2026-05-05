"""Runtime service wrapper around AuthLayer.

Provides session orchestration, connection management, and credential
resolution APIs.  This is the boundary that the daemon server, CLI client,
and proxy all consume.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from loguru import logger

from authsome.runtime.models import (
    CredentialResolutionResponse,
    RuntimeSession,
    SessionState,
)
from authsome.utils import utc_now

if TYPE_CHECKING:
    from authsome.auth import AuthLayer


class AuthRuntimeService:
    """Runtime-facing service wrapper around :class:`AuthLayer`.

    Manages session lifecycle and exposes credential resolution for
    the proxy and CLI consumers.
    """

    def __init__(self, auth: AuthLayer) -> None:
        self._auth = auth
        self._sessions: dict[str, RuntimeSession] = {}

    @property
    def auth(self) -> AuthLayer:
        """Return the underlying AuthLayer."""
        return self._auth

    # ── Session management ────────────────────────────────────────────────

    def start_login_session(
        self,
        *,
        provider: str,
        profile: str,
        connection_name: str = "default",
        flow_type: str,
        scopes: list[str] | None = None,
        force: bool = False,
        base_url: str | None = None,
    ) -> RuntimeSession:
        """Create a new login session and record it."""
        session_id = f"sess_{uuid.uuid4().hex[:12]}"
        session = RuntimeSession(
            session_id=session_id,
            provider=provider,
            profile=profile,
            connection_name=connection_name,
            flow_type=flow_type,
        )
        self._sessions[session_id] = session

        from authsome.auth.models.enums import FlowType

        flow_enum = FlowType(flow_type) if flow_type else None

        # Check if already connected first (unless force=True)
        if not force:
            try:
                existing = self._auth.get_connection(provider, connection_name)
                if existing and self._auth._connection_is_valid(existing):
                    if self._auth._requested_context_matches(existing, scopes=scopes, base_url=base_url):
                        session.state = "completed"
                        session.status_message = "Already connected"
                        return session
            except Exception:
                pass

        self._auth.begin_login_flow(
            session=session,
            scopes=scopes,
            flow_override=flow_enum,
            force=force,
            base_url=base_url,
        )
        logger.debug(
            "Created login session: session_id={} provider={} flow={}",
            session_id,
            provider,
            flow_type,
        )
        return session

    def get_session(self, session_id: str) -> RuntimeSession:
        """Return a session by ID."""
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Session not found: {session_id}")
        return session

    def list_sessions(self) -> list[RuntimeSession]:
        """Return all active sessions."""
        return list(self._sessions.values())

    def update_session_state(
        self,
        session_id: str,
        state: str,
        *,
        status_message: str | None = None,
        error_message: str | None = None,
    ) -> RuntimeSession:
        """Transition a session to a new state."""
        session = self.get_session(session_id)
        session.state = state
        session.updated_at = utc_now()
        if status_message is not None:
            session.status_message = status_message
        if error_message is not None:
            session.error_message = error_message
        return session

    def complete_login_session(
        self,
        session_id: str,
        *,
        provider: str,
        connection_name: str = "default",
        scopes: list[str] | None = None,
        flow_override: str | None = None,
        force: bool = False,
        input_provider: Any | None = None,
        base_url: str | None = None,
        callback_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute the actual login flow and update session state.

        This drives the synchronous CLI login experience: create a
        session, run the flow to completion, and return a result dict.
        """
        session = self.get_session(session_id)
        if session.state in ("completed", "failed"):
            return {
                "session_id": session_id,
                "status": "already_processed",
                "provider": session.provider,
                "connection": session.connection_name,
            }

        self.update_session_state(session_id, SessionState.PROCESSING)

        try:
            # For API_KEY, if we don't have callback_data, check session payload or input_provider
            if session.flow_type == "api_key" and (not callback_data or "api_key" not in callback_data):
                api_key = session.payload.get("api_key")
                if api_key:
                    callback_data = {"api_key": api_key}
                elif input_provider and hasattr(input_provider, "collect"):
                    definition = self._auth.get_provider(provider)
                    from authsome.auth.input_provider import InputField

                    fields = [InputField(name="api_key", label="API Key", secret=True)]
                    if definition.api_key and definition.api_key.key_pattern:
                        fields[0].pattern = definition.api_key.key_pattern
                        fields[0].pattern_hint = definition.api_key.key_pattern_hint
                    inputs = input_provider.collect(fields)
                    callback_data = {"api_key": inputs.get("api_key")}

            record = self._auth.resume_login_flow(session, callback_data or {})

            if record is not None:
                self.update_session_state(
                    session_id,
                    SessionState.COMPLETED,
                    status_message="Login successful",
                )

                return {
                    "session_id": session_id,
                    "status": "success",
                    "provider": session.provider,
                    "connection": session.connection_name,
                    "record_status": record.status.value,
                }
            else:
                self.update_session_state(session_id, SessionState.WAITING_FOR_USER)
                return {
                    "session_id": session_id,
                    "status": "pending",
                    "provider": session.provider,
                    "connection": session.connection_name,
                }

        except Exception as exc:
            self.update_session_state(
                session_id,
                SessionState.FAILED,
                error_message=str(exc),
            )
            raise

    def resume_login_session(
        self,
        session_id: str,
        callback_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Submit user/callback data to resume the flow and complete it."""
        session = self.get_session(session_id)
        return self.complete_login_session(
            session_id,
            provider=session.provider,
            connection_name=session.connection_name,
            callback_data=callback_data,
        )

    # ── Connection management ─────────────────────────────────────────────

    def list_connections(self) -> dict[str, Any]:
        """Return connections and provider metadata for the list command."""
        raw_list = self._auth.list_connections()
        by_source = self._auth.list_providers_by_source()
        return {
            "connections": raw_list,
            "by_source": {
                source: [p.model_dump(mode="json") for p in providers] for source, providers in by_source.items()
            },
        }

    def get_connection(self, provider: str, connection_name: str = "default") -> dict[str, Any]:
        record = self._auth.get_connection(provider, connection_name)
        return record.model_dump(mode="json")

    def get_provider(self, provider: str) -> dict[str, Any]:
        definition = self._auth.get_provider(provider)
        return definition.model_dump(mode="json")

    def register_provider(self, definition_dict: dict[str, Any], force: bool = False) -> None:
        from authsome.auth.models.provider import ProviderDefinition

        definition = ProviderDefinition.model_validate(definition_dict)
        self._auth.register_provider(definition, force=force)

    def logout(self, provider: str, connection_name: str = "default") -> None:
        self._auth.logout(provider, connection_name)

    def revoke(self, provider: str, connection_name: str = "default") -> None:
        self._auth.revoke(provider)

    def remove(self, provider: str) -> None:
        self._auth.remove(provider)

    def export(self, provider: str, connection_name: str = "default", format: str = "env") -> str:
        from authsome.auth.models.enums import ExportFormat

        return self._auth.export(provider, connection_name, format=ExportFormat(format))

    def whoami(self) -> dict[str, Any]:
        from authsome import __version__

        config = self._auth.app_store.get_config()
        enc_mode = config.encryption.mode if config.encryption else "local_key"
        home = self._auth.app_store.home
        if enc_mode == "local_key":
            enc_desc = f"Local Key ({home / 'master.key'})"
        elif enc_mode == "keyring":
            enc_desc = "OS Keyring"
        else:
            enc_desc = enc_mode

        return {
            "version": __version__,
            "active_profile": self._auth.identity,
            "home": str(home),
            "encryption_backend": enc_desc,
        }

    def doctor(self) -> dict[str, Any]:
        # We already have vault/auth/etc in self._auth
        # self._auth.vault is available.
        # Let's just use a thin wrapper for diagnostics.
        results = {
            "home": str(self._auth.app_store.home),
            "encryption": False,
            "store": False,
            "providers_count": 0,
            "profiles_count": 0,
            "issues": [],
        }
        try:
            self._auth.vault.put("__doctor_test__", "ok", profile=self._auth.identity)
            val = self._auth.vault.get("__doctor_test__", profile=self._auth.identity)
            self._auth.vault.delete("__doctor_test__", profile=self._auth.identity)
            results["encryption"] = True
            results["store"] = val == "ok"
        except Exception as exc:
            results["issues"].append(f"Vault: {exc}")

        try:
            results["providers_count"] = len(self._auth.list_providers())
        except Exception as exc:
            results["issues"].append(f"Providers: {exc}")

        try:
            results["profiles_count"] = len(self._auth.list_profiles())
        except Exception as exc:
            results["issues"].append(f"Profiles: {exc}")

        return results

    # ── Credential resolution ─────────────────────────────────────────────

    def resolve_request_credentials(
        self,
        *,
        provider: str,
        connection_name: str = "default",
        profile: str | None = None,
    ) -> dict[str, str]:
        """Resolve auth headers for a provider connection.

        Used by the proxy for just-in-time header injection and by
        CLI credential reads.
        """
        previous_identity = self._auth._identity
        try:
            if profile is not None:
                self._auth._identity = profile
            headers = self._auth.get_auth_headers(provider, connection_name)
            return headers
        finally:
            self._auth._identity = previous_identity

    def resolve_credential_response(
        self,
        *,
        provider: str,
        connection_name: str = "default",
        profile: str | None = None,
    ) -> CredentialResolutionResponse:
        """Return a structured credential resolution response."""
        headers = self.resolve_request_credentials(
            provider=provider,
            connection_name=connection_name,
            profile=profile,
        )
        return CredentialResolutionResponse(
            provider=provider,
            connection_name=connection_name,
            profile=profile or self._auth.identity,
            headers=headers,
        )
