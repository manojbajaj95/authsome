"""AuthService — authentication and credential lifecycle service.

Owns OAuth flows, token refresh, login/logout/revoke.
Receives Vault and ProviderRegistry as dependencies.
Does not touch encryption directly — all persistence goes through the Vault.
"""

from __future__ import annotations

import json
import re
from datetime import timedelta
from typing import Any

import requests as http_client
from loguru import logger

from authsome.auth.flows.api_key import ApiKeyFlow
from authsome.auth.flows.base import AuthFlow
from authsome.auth.flows.dcr_pkce import DcrPkceFlow
from authsome.auth.flows.device_code import DeviceCodeFlow
from authsome.auth.flows.pkce import PkceFlow
from authsome.auth.input_provider import InputField
from authsome.auth.models.connection import (
    ConnectionRecord,
    ProviderClientRecord,
    ProviderMetadataRecord,
    ProviderStateRecord,
)
from authsome.auth.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.auth.models.profile import ProfileMetadata
from authsome.auth.models.provider import ProviderDefinition
from authsome.auth.providers import ProviderRegistry
from authsome.auth.sessions import AuthSession
from authsome.errors import (
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    ProfileNotFoundError,
    RefreshFailedError,
    TokenExpiredError,
    UnsupportedFlowError,
)
from authsome.store.interfaces import AppStore
from authsome.utils import build_store_key, utc_now
from authsome.vault import Vault

_NEAR_EXPIRY_SECONDS = 300

_FLOW_HANDLERS: dict[FlowType, type[AuthFlow]] = {
    FlowType.PKCE: PkceFlow,
    FlowType.DEVICE_CODE: DeviceCodeFlow,
    FlowType.DCR_PKCE: DcrPkceFlow,
    FlowType.API_KEY: ApiKeyFlow,
}


class AuthService:
    """
    Authentication and credential lifecycle service.

    All credential reads and writes go through self._vault.
    Key construction (profile:<identity>:<provider>:...) lives here.
    """

    def __init__(
        self,
        vault: Vault,
        registry: ProviderRegistry,
        app_store: AppStore,
        identity: str | None = None,
    ) -> None:
        self._vault = vault
        self._registry = registry
        self._app_store = app_store
        self._identity = identity or "default"

    @property
    def vault(self) -> Vault:
        return self._vault

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def app_store(self) -> AppStore:
        return self._app_store

    # ── Provider operations ───────────────────────────────────────────────

    def list_providers(self) -> list[ProviderDefinition]:
        return self._registry.list_providers()

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        return self._registry.list_providers_by_source()

    def get_provider(self, name: str) -> ProviderDefinition:
        return self._registry.get_provider(name)

    def register_provider(self, definition: ProviderDefinition, *, force: bool = False) -> None:
        self._registry.register_provider(definition, force=force)

    # ── Connection operations ─────────────────────────────────────────────

    def list_connections(self) -> list[dict[str, Any]]:
        prefix = f"profile:{self._identity}:"
        keys = self._vault.list(prefix, profile=self._identity)

        providers: dict[str, list[dict[str, Any]]] = {}
        defaults: dict[str, str] = {}
        for key in keys:
            parts = key.split(":")
            if len(parts) >= 5 and parts[3] == "connection":
                provider_name = parts[2]
                connection_name = parts[4]
                if provider_name not in defaults:
                    meta_key = build_store_key(profile=self._identity, provider=provider_name, record_type="metadata")
                    meta_json = self._vault.get(meta_key, profile=self._identity)
                    if meta_json:
                        defaults[provider_name] = ProviderMetadataRecord.model_validate_json(
                            meta_json
                        ).default_connection
                    else:
                        defaults[provider_name] = "default"
                record_json = self._vault.get(key, profile=self._identity)
                if record_json:
                    record = self._load_connection_record(record_json, key)
                    if record is None:
                        continue
                    if provider_name not in providers:
                        providers[provider_name] = []
                    providers[provider_name].append(
                        {
                            "connection_name": connection_name,
                            "is_default": connection_name == defaults.get(provider_name, "default"),
                            "auth_type": record.auth_type.value,
                            "status": record.status.value,
                            "scopes": record.scopes,
                            "base_url": record.base_url,
                            "host_url": record.host_url,
                            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
                        }
                    )

        return [
            {"name": pname, "default_connection": defaults.get(pname, "default"), "connections": conns}
            for pname, conns in sorted(providers.items())
        ]

    def get_connection(
        self,
        provider: str,
        connection: str = "default",
    ) -> ConnectionRecord:
        connection = self.resolve_connection_name(provider, connection)
        key = build_store_key(
            profile=self._identity, provider=provider, record_type="connection", connection=connection
        )
        record_json = self._vault.get(key, profile=self._identity)
        if not record_json:
            raise ConnectionNotFoundError(provider=provider, connection=connection, profile=self._identity)
        record = self._load_connection_record(record_json, key)
        if record is None:
            raise AuthsomeError(
                f"Stored credentials for '{provider}' use the old v1 format. "
                "Please run: authsome revoke {provider} && authsome login {provider}"
            )
        return record

    def resolve_connection_name(self, provider: str, connection: str | None = None) -> str:
        """Resolve an optional connection name to the provider default."""
        if connection:
            return connection
        meta_key = build_store_key(profile=self._identity, provider=provider, record_type="metadata")
        existing_json = self._vault.get(meta_key, profile=self._identity)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
            return metadata.default_connection
        return "default"

    def set_default_connection(self, provider: str, connection: str) -> None:
        """Set the default connection for a provider."""
        self.get_connection(provider, connection)
        meta_key = build_store_key(profile=self._identity, provider=provider, record_type="metadata")
        existing_json = self._vault.get(meta_key, profile=self._identity)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
        else:
            metadata = ProviderMetadataRecord(profile=self._identity, provider=provider)
        if connection not in metadata.connection_names:
            metadata.connection_names.append(connection)
        metadata.default_connection = connection
        metadata.last_used_connection = connection
        self._vault.put(meta_key, metadata.model_dump_json(), profile=self._identity)

    # ── Authentication ────────────────────────────────────────────────────

    def get_required_inputs(
        self,
        session: AuthSession,
        scopes: list[str] | None = None,
        base_url: str | None = None,
    ) -> list[InputField]:
        """Determine what inputs are missing for a given session."""
        from authsome.auth.input_provider import InputField

        provider = session.provider
        definition = self.get_provider(provider)
        flow_type = FlowType(session.flow_type)
        client_record = self._get_provider_client_credentials(provider)

        flow_base_url = base_url or (client_record.base_url if client_record else None)
        flow_client_id = client_record.client_id if client_record else None
        persisted_scopes = client_record.scopes if client_record else None

        fields: list[InputField] = []

        if definition.oauth and definition.oauth.base_url and not flow_base_url:
            fields.append(
                InputField(
                    name="base_url",
                    label="Base URL",
                    secret=False,
                    default=definition.oauth.base_url,
                )
            )
            fields.append(
                InputField(
                    name="host_url",
                    label="API Host URL",
                    secret=False,
                    default=definition.host_url or "",
                )
            )

        if flow_type == FlowType.PKCE and not flow_client_id:
            fields.append(InputField(name="client_id", label="Client ID", secret=False))
            fields.append(InputField(name="client_secret", label="Client Secret (Optional)", secret=True, default=""))
        elif flow_type == FlowType.DEVICE_CODE and not flow_client_id:
            fields.append(
                InputField(
                    name="client_id",
                    label="Client ID (leave blank for public device flow)",
                    secret=False,
                    default="",
                )
            )
            fields.append(InputField(name="client_secret", label="Client Secret (Optional)", secret=True, default=""))

        if flow_type in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE):
            if scopes is None and persisted_scopes is None:
                default_scopes = (
                    ",".join(definition.oauth.scopes) if definition.oauth and definition.oauth.scopes else ""
                )
                fields.append(
                    InputField(name="scopes", label="Scopes (comma-separated)", secret=False, default=default_scopes)
                )

        if flow_type == FlowType.API_KEY:
            api_key_field = InputField(name="api_key", label="API Key", secret=True)
            if definition.api_key and definition.api_key.key_pattern:
                api_key_field.pattern = definition.api_key.key_pattern
                api_key_field.pattern_hint = definition.api_key.key_pattern_hint
            fields.append(api_key_field)

        return fields

    def save_inputs(self, session: AuthSession, inputs: dict[str, str]) -> None:
        """Save collected inputs to the Vault or session payload."""
        from authsome.auth.models.connection import ProviderClientRecord

        provider = session.provider
        flow_type = FlowType(session.flow_type)
        client_record = self._get_provider_client_credentials(provider)

        if flow_type in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE):
            if client_record is None:
                client_record = ProviderClientRecord(profile=self._identity, provider=provider)
            if inputs.get("base_url"):
                client_record.base_url = inputs["base_url"]
                session.payload["base_url"] = inputs["base_url"]
            if inputs.get("host_url"):
                client_record.host_url = inputs["host_url"]
            if inputs.get("client_id"):
                client_record.client_id = inputs["client_id"]
            if inputs.get("client_secret"):
                client_record.client_secret = inputs["client_secret"]
            if "scopes" in inputs:
                scopes_input = inputs["scopes"].strip()
                client_record.scopes = [s.strip() for s in scopes_input.split(",") if s.strip()] if scopes_input else []
            self._save_provider_client_credentials(client_record)
        elif flow_type == FlowType.API_KEY:
            api_key = inputs.get("api_key")
            if api_key:
                session.payload["api_key"] = api_key

    def begin_login_flow(
        self,
        session: AuthSession,
        scopes: list[str] | None = None,
        flow_override: FlowType | None = None,
        force: bool = False,
        base_url: str | None = None,
    ) -> None:
        provider = session.provider
        connection_name = session.connection_name
        definition = self.get_provider(provider)

        flow_type = flow_override or FlowType(session.flow_type)
        handler_cls = _FLOW_HANDLERS.get(flow_type)
        if handler_cls is None:
            raise UnsupportedFlowError(flow_type.value, provider=provider)

        handler = handler_cls()
        client_record = self._get_provider_client_credentials(provider)

        flow_client_id = client_record.client_id if client_record else None
        flow_client_secret = client_record.client_secret if client_record else None
        flow_base_url = base_url or (client_record.base_url if client_record else None)

        final_scopes = (
            scopes
            if scopes is not None
            else (client_record.scopes if client_record and client_record.scopes is not None else None)
        )

        resolved_definition = definition.resolve_urls(flow_base_url)

        handler.begin(
            provider=resolved_definition,
            profile=self._identity,
            connection_name=connection_name,
            runtime_session=session,
            scopes=final_scopes,
            client_id=flow_client_id,
            client_secret=flow_client_secret,
            base_url=flow_base_url,
        )

        final_scopes = (
            scopes
            if scopes is not None
            else (client_record.scopes if client_record and client_record.scopes is not None else None)
        )

        resolved_definition = definition.resolve_urls(flow_base_url)

        handler.begin(
            provider=resolved_definition,
            profile=self._identity,
            connection_name=connection_name,
            runtime_session=session,
            scopes=final_scopes,
            client_id=flow_client_id,
            client_secret=flow_client_secret,
            base_url=flow_base_url,
        )

    def resume_login_flow(
        self,
        session: AuthSession,
        callback_data: dict[str, Any],
    ) -> ConnectionRecord | None:
        provider = session.provider
        connection_name = session.connection_name
        definition = self.get_provider(provider)

        from authsome.auth.models.enums import FlowType

        flow_type = FlowType(session.flow_type)
        handler_cls = _FLOW_HANDLERS.get(flow_type)
        if handler_cls is None:
            raise UnsupportedFlowError(flow_type.value, provider=provider)

        handler = handler_cls()
        client_record = self._get_provider_client_credentials(provider)

        flow_client_id = client_record.client_id if client_record else None
        flow_client_secret = client_record.client_secret if client_record else None

        flow_base_url = session.payload.get("base_url") or (client_record.base_url if client_record else None)
        resolved_definition = definition.resolve_urls(flow_base_url)

        result = handler.resume(
            provider=resolved_definition,
            profile=self._identity,
            connection_name=connection_name,
            runtime_session=session,
            callback_data=callback_data,
            client_id=flow_client_id,
            client_secret=flow_client_secret,
        )

        if result is None or result.connection is None:
            return None

        if result.client_record is not None:
            if client_record is None:
                client_record = ProviderClientRecord(profile=self._identity, provider=provider)
            client_record.client_id = result.client_record.client_id
            client_record.client_secret = result.client_record.client_secret
            client_record.base_url = result.client_record.base_url or client_record.base_url
            self._save_provider_client_credentials(client_record)

        result.connection.base_url = flow_base_url
        result.connection.host_url = resolved_definition.host_url

        self._save_connection(result.connection)
        self._update_provider_metadata(provider, connection_name)

        logger.info("Login successful: provider={} connection={} profile={}", provider, connection_name, self._identity)
        return result.connection

    def background_resume(self, session: AuthSession) -> None:
        """Resume a flow in a background thread."""
        from authsome.auth.sessions import AuthSessionStatus

        try:
            self.resume_login_flow(session, {})
            session.state = AuthSessionStatus.COMPLETED
            session.status_message = "Login successful"
        except Exception as e:
            session.state = AuthSessionStatus.FAILED
            session.error_message = str(e)

    @staticmethod
    def _connection_is_valid(record: ConnectionRecord) -> bool:
        if record.status != ConnectionStatus.CONNECTED:
            return False
        if record.expires_at is None:
            return True
        return utc_now() < record.expires_at

    @classmethod
    def _requested_context_matches(
        cls,
        record: ConnectionRecord,
        *,
        scopes: list[str] | None,
        base_url: str | None,
    ) -> bool:
        if scopes is not None and cls._normalize_scopes(scopes) != cls._normalize_scopes(record.scopes):
            return False
        if base_url is not None and cls._normalize_base_url(base_url) != cls._normalize_base_url(record.base_url):
            return False
        return True

    @staticmethod
    def _normalize_scopes(scopes: list[str] | None) -> set[str]:
        return {scope.strip() for scope in scopes or [] if scope.strip()}

    @staticmethod
    def _normalize_base_url(base_url: str | None) -> str | None:
        if not base_url:
            return None
        raw = base_url.strip().rstrip("/")
        from urllib.parse import urlsplit, urlunsplit

        parsed = urlsplit(raw)
        if not parsed.scheme or not parsed.netloc:
            return raw
        return urlunsplit(
            (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )

    @staticmethod
    def _build_docs_hints(definition: ProviderDefinition, flow_type: FlowType) -> list[dict[str, Any]]:
        """Convert provider docs URL into a bridge instruction block."""
        if not definition.docs:
            return []

        if flow_type not in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE, FlowType.API_KEY):
            return []

        return [
            {
                "type": "instructions",
                "label": "Instructions",
                "url": definition.docs,
            }
        ]

    # ── Token operations ──────────────────────────────────────────────────

    def get_access_token(self, provider: str, connection: str = "default") -> str:
        record = self.get_connection(provider, connection)
        if record.auth_type == AuthType.API_KEY:
            return self._get_api_key(record)
        if record.auth_type == AuthType.OAUTH2:
            return self._get_oauth_token(record, provider, connection)
        raise CredentialMissingError(f"Unsupported auth type: {record.auth_type}", provider=provider)

    def get_auth_headers(self, provider: str, connection: str = "default") -> dict[str, str]:
        connection = self.resolve_connection_name(provider, connection)
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection)

        if record.auth_type == AuthType.OAUTH2:
            token = self.get_access_token(provider, connection)
            return {"Authorization": f"Bearer {token}"}

        if record.auth_type == AuthType.API_KEY:
            api_key_value = self._get_api_key(record)
            if definition.api_key:
                header_name = definition.api_key.header_name
                prefix = definition.api_key.header_prefix
                if prefix:
                    return {header_name: f"{prefix} {api_key_value}"}
                return {header_name: api_key_value}
            return {"Authorization": f"Bearer {api_key_value}"}

        raise CredentialMissingError(f"Cannot build headers for auth type: {record.auth_type}", provider=provider)

    # ── Lifecycle operations ──────────────────────────────────────────────

    def logout(self, provider: str, connection: str = "default") -> None:
        definition = self.get_provider(provider)
        try:
            record = self.get_connection(provider, connection)
        except ConnectionNotFoundError:
            return

        if record.auth_type == AuthType.OAUTH2 and (record.access_token or record.refresh_token):
            resolved_definition = definition.resolve_urls(record.base_url)
            if resolved_definition.oauth and resolved_definition.oauth.revocation_url:
                # Revoke access token
                if record.access_token:
                    try:
                        http_client.post(
                            resolved_definition.oauth.revocation_url, data={"token": record.access_token}, timeout=15
                        )
                    except Exception as exc:
                        logger.warning("Access token revocation failed (continuing): {}", exc)
                # Revoke refresh token
                if record.refresh_token:
                    try:
                        http_client.post(
                            resolved_definition.oauth.revocation_url, data={"token": record.refresh_token}, timeout=15
                        )
                    except Exception as exc:
                        logger.warning("Refresh token revocation failed (continuing): {}", exc)

        key = build_store_key(
            profile=self._identity, provider=provider, record_type="connection", connection=connection
        )
        self._vault.delete(key, profile=self._identity)
        self._remove_from_provider_metadata(provider, connection)

    def revoke(self, provider: str) -> None:
        self.get_provider(provider)
        meta_key = build_store_key(profile=self._identity, provider=provider, record_type="metadata")
        existing_json = self._vault.get(meta_key, profile=self._identity)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
            for conn_name in list(metadata.connection_names):
                self.logout(provider, connection=conn_name)
        self._vault.delete(meta_key, profile=self._identity)
        client_key = build_store_key(profile=self._identity, provider=provider, record_type="client")
        self._vault.delete(client_key, profile=self._identity)

    def remove(self, provider: str) -> None:
        """Revoke all tokens and remove the provider definition if it is local."""
        self.revoke(provider)
        if self._registry.is_local(provider):
            self._registry._app_store.delete_provider(provider)
            logger.info("Removed local provider definition: {}", provider)
        else:
            logger.info("Revoked bundled provider: {} (definition kept)", provider)

    # ── Export operations ─────────────────────────────────────────────────

    def export(
        self,
        provider: str | None = None,
        connection: str = "default",
        format: ExportFormat = ExportFormat.ENV,
    ) -> str:
        """Export credential material in selected format."""
        values = self.get_export_values(provider, connection)
        return self._format_export_values(values, format)

    def get_export_values(self, provider: str | None = None, connection: str = "default") -> dict[str, str]:
        """Return a dictionary of exportable credential values."""
        if provider is None:
            values: dict[str, str] = {}
            for provider_record in self.list_connections():
                provider_name = provider_record["name"]
                for connection_record in provider_record["connections"]:
                    connection_name = connection_record["connection_name"]
                    for env_name, env_value in self._export_connection_values(provider_name, connection_name).items():
                        if env_name in values:
                            env_name = self._disambiguate_export_name(env_name, provider_name, connection_name, values)
                        values[env_name] = env_value
            return values

        return self._export_connection_values(provider, connection)

    def _export_connection_values(self, provider: str, connection: str) -> dict[str, str]:
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection)
        values: dict[str, str] = {}
        export_map = definition.export.env if definition.export else {}

        if record.auth_type == AuthType.OAUTH2:
            if record.access_token:
                env_name = export_map.get("access_token", f"{self._export_name_part(provider)}_ACCESS_TOKEN")
                values[env_name] = record.access_token
            if record.refresh_token:
                env_name = export_map.get("refresh_token", f"{self._export_name_part(provider)}_REFRESH_TOKEN")
                values[env_name] = record.refresh_token
        elif record.auth_type == AuthType.API_KEY:
            if record.api_key:
                env_name = export_map.get("api_key", f"{self._export_name_part(provider)}_API_KEY")
                values[env_name] = record.api_key

        return values

    def _format_export_values(self, values: dict[str, str], format: ExportFormat) -> str:
        if format == ExportFormat.ENV:
            return "\n".join(f"{k}={v}" for k, v in values.items())
        if format == ExportFormat.SHELL:
            return "\n".join(f"export {k}={v}" for k, v in values.items())
        if format == ExportFormat.JSON:
            return json.dumps(values, indent=2)
        return ""

    def _disambiguate_export_name(
        self, env_name: str, provider: str, connection: str, existing_values: dict[str, str]
    ) -> str:
        suffix = "_".join(
            part
            for part in (
                self._export_name_part(provider),
                self._export_name_part(connection),
            )
            if part
        )
        candidate = f"{env_name}_{suffix}" if suffix else env_name
        counter = 2
        while candidate in existing_values:
            candidate = f"{env_name}_{suffix}_{counter}" if suffix else f"{env_name}_{counter}"
            counter += 1
        return candidate

    def _export_name_part(self, value: str) -> str:
        return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")

    # ── Profile operations ────────────────────────────────────────────────

    def list_profiles(self) -> list[ProfileMetadata]:
        return self._app_store.list_profiles()

    def get_profile(self, name: str) -> ProfileMetadata:
        return self._app_store.get_profile(name)

    def set_default_profile(self, name: str) -> None:
        self._app_store.get_profile(name)
        config = self._app_store.get_config()
        config.default_profile = name
        self._app_store.save_config(config)

    def create_profile(self, name: str, description: str = "") -> ProfileMetadata:
        try:
            self._app_store.get_profile(name)
            raise ValueError(f"Profile {name} already exists")
        except ProfileNotFoundError:
            pass

        now = utc_now()
        metadata = ProfileMetadata(
            name=name,
            created_at=now,
            updated_at=now,
            description=description,
        )
        self._app_store.save_profile(metadata)
        return metadata

    # ── Internal helpers ──────────────────────────────────────────────────

    def _load_connection_record(self, record_json: str, key: str) -> ConnectionRecord | None:
        """Load and validate a connection record, detecting v1 format."""
        try:
            data = json.loads(record_json)
        except json.JSONDecodeError:
            logger.warning("Corrupt record at key {}", key)
            return None

        if data.get("schema_version", 1) < 2:
            return None  # v1 data — caller handles detection

        return ConnectionRecord.model_validate(data)

    def _save_connection(self, record: ConnectionRecord) -> None:
        key = build_store_key(
            profile=self._identity,
            provider=record.provider,
            record_type="connection",
            connection=record.connection_name,
        )
        self._vault.put(key, record.model_dump_json(), profile=self._identity)

    def _get_provider_client_credentials(self, provider: str) -> ProviderClientRecord | None:
        key = build_store_key(profile=self._identity, provider=provider, record_type="client")
        record_json = self._vault.get(key, profile=self._identity)
        if record_json:
            return ProviderClientRecord.model_validate_json(record_json)
        return None

    def _save_provider_client_credentials(self, record: ProviderClientRecord) -> None:
        key = build_store_key(profile=self._identity, provider=record.provider, record_type="client")
        self._vault.put(key, record.model_dump_json(), profile=self._identity)

    def _update_provider_metadata(self, provider: str, connection_name: str) -> None:
        meta_key = build_store_key(profile=self._identity, provider=provider, record_type="metadata")
        existing_json = self._vault.get(meta_key, profile=self._identity)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
        else:
            metadata = ProviderMetadataRecord(profile=self._identity, provider=provider)
        if connection_name not in metadata.connection_names:
            metadata.connection_names.append(connection_name)
        metadata.last_used_connection = connection_name
        self._vault.put(meta_key, metadata.model_dump_json(), profile=self._identity)

    def _remove_from_provider_metadata(self, provider: str, connection_name: str) -> None:
        meta_key = build_store_key(profile=self._identity, provider=provider, record_type="metadata")
        existing_json = self._vault.get(meta_key, profile=self._identity)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
            if connection_name in metadata.connection_names:
                metadata.connection_names.remove(connection_name)
            if metadata.last_used_connection == connection_name:
                metadata.last_used_connection = metadata.connection_names[0] if metadata.connection_names else None
            self._vault.put(meta_key, metadata.model_dump_json(), profile=self._identity)

    def _get_api_key(self, record: ConnectionRecord) -> str:
        if record.api_key is None:
            raise CredentialMissingError("No API key stored in connection record", provider=record.provider)
        return record.api_key

    def _get_oauth_token(self, record: ConnectionRecord, provider: str, connection: str) -> str:
        if record.access_token is None:
            raise CredentialMissingError("No access token stored", provider=provider)

        now = utc_now()
        if record.expires_at:
            near_expiry = record.expires_at - timedelta(seconds=_NEAR_EXPIRY_SECONDS)
            if now < near_expiry:
                return record.access_token

            if record.refresh_token:
                try:
                    refreshed = self._refresh_token(record, provider)
                    if refreshed.access_token is None:
                        raise RefreshFailedError("Refreshed record missing access token", provider=provider)
                    return refreshed.access_token
                except RefreshFailedError as exc:
                    if now < record.expires_at:
                        logger.warning(
                            "Token refresh failed for provider={} connection={} profile={}: {}; "
                            "using cached token until {}. Re-authenticate with: authsome login {}",
                            provider,
                            connection,
                            self._identity,
                            exc,
                            record.expires_at.isoformat(),
                            provider,
                        )
                        return record.access_token
                    record.status = ConnectionStatus.EXPIRED
                    self._save_connection(record)
                    raise
            else:
                if now >= record.expires_at:
                    record.status = ConnectionStatus.EXPIRED
                    self._save_connection(record)
                    raise TokenExpiredError(provider=provider)
                return record.access_token
        else:
            return record.access_token

    def _refresh_token(self, record: ConnectionRecord, provider_name: str) -> ConnectionRecord:
        definition = self.get_provider(provider_name)
        if definition.oauth is None:
            raise RefreshFailedError("No OAuth config", provider=provider_name)
        if record.refresh_token is None:
            raise RefreshFailedError("No refresh token available", provider=provider_name)

        client_record = self._get_provider_client_credentials(provider_name)
        client_id = client_record.client_id if client_record else None
        client_secret = client_record.client_secret if client_record else None

        if not client_id:
            raise RefreshFailedError("No client_id available for refresh", provider=provider_name)

        state_record = self._get_or_create_provider_state(provider_name)
        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": record.refresh_token,
            "client_id": client_id,
        }
        if client_secret:
            payload["client_secret"] = client_secret

        base_url = record.base_url or (client_record.base_url if client_record else None)
        resolved_definition = definition.resolve_urls(base_url)
        if not resolved_definition.oauth:
            raise RefreshFailedError("Resolved provider missing OAuth configuration", provider=provider_name)

        try:
            resp = http_client.post(
                resolved_definition.oauth.token_url,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            token = resp.json()
        except Exception as exc:
            state_record.last_refresh_at = utc_now()
            state_record.last_refresh_error = str(exc)
            self._save_provider_state(state_record)
            raise RefreshFailedError(str(exc), provider=provider_name) from exc

        now = utc_now()
        record.access_token = token["access_token"]
        if "refresh_token" in token:
            record.refresh_token = token["refresh_token"]
        if "expires_in" in token:
            record.expires_at = now + timedelta(seconds=int(token["expires_in"]))
        record.obtained_at = now
        record.status = ConnectionStatus.CONNECTED
        self._save_connection(record)

        state_record.last_refresh_at = now
        state_record.last_refresh_error = None
        self._save_provider_state(state_record)

        logger.info("Token refreshed: provider={}", provider_name)
        return record

    def _get_or_create_provider_state(self, provider: str) -> ProviderStateRecord:
        key = build_store_key(profile=self._identity, provider=provider, record_type="state")
        existing = self._vault.get(key, profile=self._identity)
        if existing:
            return ProviderStateRecord.model_validate_json(existing)
        return ProviderStateRecord(provider=provider, profile=self._identity)

    def _save_provider_state(self, state: ProviderStateRecord) -> None:
        key = build_store_key(profile=self._identity, provider=state.provider, record_type="state")
        self._vault.put(key, state.model_dump_json(), profile=self._identity)
