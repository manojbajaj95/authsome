"""AuthLayer — authentication and credential lifecycle layer.

Owns OAuth flows, token refresh, login/logout/revoke.
Receives Vault and ProviderRegistry as dependencies.
Does not touch encryption directly — all persistence goes through the Vault.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import requests as http_client
from loguru import logger

from authsome.auth.flows.api_key import ApiKeyFlow
from authsome.auth.flows.base import AuthFlow
from authsome.auth.flows.dcr_pkce import DcrPkceFlow
from authsome.auth.flows.device_code import DeviceCodeFlow
from authsome.auth.flows.pkce import PkceFlow
from authsome.auth.input_provider import BridgeInputProvider, InputField, InputProvider
from authsome.auth.models.connection import (
    ConnectionRecord,
    ProviderClientRecord,
    ProviderMetadataRecord,
    ProviderStateRecord,
)
from authsome.auth.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.auth.models.provider import ProviderDefinition
from authsome.auth.providers.registry import ProviderRegistry
from authsome.errors import (
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    ProfileNotFoundError,
    RefreshFailedError,
    TokenExpiredError,
    UnsupportedFlowError,
)
from authsome.utils import build_store_key, utc_now
from authsome.vault import Vault

_NEAR_EXPIRY_SECONDS = 300

_FLOW_HANDLERS: dict[FlowType, type[AuthFlow]] = {
    FlowType.PKCE: PkceFlow,
    FlowType.DEVICE_CODE: DeviceCodeFlow,
    FlowType.DCR_PKCE: DcrPkceFlow,
    FlowType.API_KEY: ApiKeyFlow,
}


class AuthLayer:
    """
    Authentication and credential lifecycle layer.

    All credential reads and writes go through self._vault.
    Key construction (profile:<identity>:<provider>:...) lives here.
    """

    def __init__(
        self,
        vault: Vault,
        registry: ProviderRegistry,
        identity: str,
        profiles_dir: Path,
    ) -> None:
        self._vault = vault
        self._registry = registry
        self._identity = identity  # profile slug
        self._profiles_dir = profiles_dir

    @property
    def registry(self) -> ProviderRegistry:
        return self._registry

    @property
    def identity(self) -> str:
        return self._identity

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
        for key in keys:
            parts = key.split(":")
            if len(parts) >= 5 and parts[3] == "connection":
                provider_name = parts[2]
                connection_name = parts[4]
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
                            "auth_type": record.auth_type.value,
                            "status": record.status.value,
                            "scopes": record.scopes,
                            "base_url": record.base_url,
                            "host_url": record.host_url,
                            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
                        }
                    )

        return [{"name": pname, "connections": conns} for pname, conns in sorted(providers.items())]

    def get_connection(
        self,
        provider: str,
        connection: str = "default",
    ) -> ConnectionRecord:
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

    # ── Authentication ────────────────────────────────────────────────────

    def login(
        self,
        provider: str,
        connection_name: str = "default",
        scopes: list[str] | None = None,
        flow_override: FlowType | None = None,
        force: bool = False,
        input_provider: InputProvider | None = None,
        base_url: str | None = None,
    ) -> ConnectionRecord:
        definition = self.get_provider(provider)

        try:
            existing = self.get_connection(provider, connection_name)
            if existing and not force:
                raise AuthsomeError(
                    f"Connection '{connection_name}' for provider '{provider}' already exists. "
                    "Use --force to overwrite."
                )
        except ConnectionNotFoundError:
            pass

        flow_type = flow_override or definition.flow
        handler_cls = _FLOW_HANDLERS.get(flow_type)
        if handler_cls is None:
            raise UnsupportedFlowError(flow_type.value, provider=provider)

        handler = handler_cls()
        client_record = self._get_provider_client_credentials(provider)

        flow_client_id = client_record.client_id if client_record else None
        flow_client_secret = client_record.client_secret if client_record else None
        flow_base_url = base_url or (client_record.base_url if client_record else None)
        flow_api_key = None
        persisted_scopes = client_record.scopes if client_record else None

        # Build list of fields that still need to be collected
        fields_to_collect: list[InputField] = []
        static_hints: list[dict] = []  # display-only hints shown in the bridge form

        if definition.oauth and definition.oauth.base_url and not flow_base_url:
            fields_to_collect.append(
                InputField(
                    name="base_url",
                    label="Base URL",
                    secret=False,
                    default=definition.oauth.base_url,
                )
            )
            # Add host_url override if base_url is present
            fields_to_collect.append(
                InputField(
                    name="host_url",
                    label="API Host URL",
                    secret=False,
                    default=definition.host_url or "",
                )
            )

        if flow_type == FlowType.PKCE and not flow_client_id:
            static_hints.append({"type": "static", "label": "Redirect URL", "value": "http://127.0.0.1:7999/callback"})
            fields_to_collect.append(InputField(name="client_id", label="Client ID", secret=False))
            fields_to_collect.append(
                InputField(name="client_secret", label="Client Secret (Optional)", secret=True, default="")
            )
        elif flow_type == FlowType.DEVICE_CODE and not flow_client_id:
            fields_to_collect.append(
                InputField(
                    name="client_id",
                    label="Client ID (leave blank for public device flow)",
                    secret=False,
                    default="",
                )
            )
            fields_to_collect.append(
                InputField(name="client_secret", label="Client Secret (Optional)", secret=True, default="")
            )

        if flow_type in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE):
            if scopes is None and persisted_scopes is None:
                default_scopes = (
                    ",".join(definition.oauth.scopes) if definition.oauth and definition.oauth.scopes else ""
                )
                fields_to_collect.append(
                    InputField(name="scopes", label="Scopes (comma-separated)", secret=False, default=default_scopes)
                )

        if flow_type == FlowType.API_KEY:
            fields_to_collect.append(InputField(name="api_key", label="API Key", secret=True))

        static_hints.extend(self._build_docs_hints(definition, flow_type))

        if fields_to_collect:
            ip: InputProvider = input_provider or BridgeInputProvider(
                title=f"{definition.display_name} Credentials",
                static_fields=static_hints,
            )
            inputs = ip.collect(fields_to_collect)

            if flow_type in (FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE):
                if client_record is None:
                    client_record = ProviderClientRecord(profile=self._identity, provider=provider)
                if inputs.get("base_url"):
                    flow_base_url = inputs["base_url"]
                    client_record.base_url = flow_base_url
                if inputs.get("host_url"):
                    client_record.host_url = inputs["host_url"]
                if inputs.get("client_id"):
                    flow_client_id = inputs["client_id"]
                    client_record.client_id = flow_client_id
                if inputs.get("client_secret"):
                    flow_client_secret = inputs["client_secret"]
                    client_record.client_secret = inputs["client_secret"]
                if "scopes" in inputs:
                    scopes_input = inputs["scopes"].strip()
                    client_record.scopes = (
                        [s.strip() for s in scopes_input.split(",") if s.strip()] if scopes_input else []
                    )
                self._save_provider_client_credentials(client_record)
            elif flow_type == FlowType.API_KEY:
                flow_api_key = inputs.get("api_key")

        final_scopes = (
            scopes
            if scopes is not None
            else (client_record.scopes if client_record and client_record.scopes is not None else None)
        )

        # Resolve URLs if base_url is present
        resolved_definition = definition.resolve_urls(flow_base_url)

        result = handler.authenticate(
            provider=resolved_definition,
            profile=self._identity,
            connection_name=connection_name,
            scopes=final_scopes,
            client_id=flow_client_id,
            client_secret=flow_client_secret,
            api_key=flow_api_key,
        )

        # If the flow registered a new OAuth client (DCR), persist it now
        if result.client_record is not None:
            if client_record is None:
                client_record = ProviderClientRecord(profile=self._identity, provider=provider)
            client_record.client_id = result.client_record.client_id
            client_record.client_secret = result.client_record.client_secret
            self._save_provider_client_credentials(client_record)

        result.connection.base_url = flow_base_url
        result.connection.host_url = (client_record.host_url if client_record else None) or resolved_definition.host_url
        self._save_connection(result.connection)
        self._update_provider_metadata(provider, connection_name)

        logger.info("Login successful: provider={} connection={} profile={}", provider, connection_name, self._identity)
        return result.connection

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

        if record.auth_type == AuthType.OAUTH2 and record.access_token:
            resolved_definition = definition.resolve_urls(record.base_url)
            if resolved_definition.oauth and resolved_definition.oauth.revocation_url:
                try:
                    http_client.post(
                        resolved_definition.oauth.revocation_url, data={"token": record.access_token}, timeout=15
                    )
                except Exception as exc:
                    logger.warning("Remote revocation failed (continuing): {}", exc)

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
        self.revoke(provider)
        local_path = self._registry.providers_dir / f"{provider}.json"
        if local_path.exists():
            local_path.unlink()
            logger.info("Removed provider definition: {}", local_path)

    # ── Export operations ─────────────────────────────────────────────────

    def export(self, provider: str, connection: str = "default", format: ExportFormat = ExportFormat.ENV) -> str:
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection)
        values: dict[str, str] = {}
        export_map = definition.export.env if definition.export else {}

        if record.auth_type == AuthType.OAUTH2:
            if record.access_token:
                env_name = export_map.get("access_token", f"{provider.upper()}_ACCESS_TOKEN")
                values[env_name] = record.access_token
            if record.refresh_token:
                env_name = export_map.get("refresh_token", f"{provider.upper()}_REFRESH_TOKEN")
                values[env_name] = record.refresh_token
        elif record.auth_type == AuthType.API_KEY:
            if record.api_key:
                env_name = export_map.get("api_key", f"{provider.upper()}_API_KEY")
                values[env_name] = record.api_key

        if format == ExportFormat.ENV:
            return "\n".join(f"{k}={v}" for k, v in values.items())
        elif format == ExportFormat.SHELL:
            return "\n".join(f"export {k}={v}" for k, v in values.items())
        elif format == ExportFormat.JSON:
            return json.dumps(values, indent=2)
        return ""

    # ── Profile operations ────────────────────────────────────────────────

    def create_profile(self, name: str, description: str | None = None) -> Any:
        from authsome.auth.models.profile import ProfileMetadata

        profile_dir = self._profiles_dir / name
        profile_dir.mkdir(parents=True, exist_ok=True)

        metadata_path = profile_dir / "metadata.json"
        if not metadata_path.exists():
            now = utc_now()
            metadata = ProfileMetadata(name=name, created_at=now, updated_at=now, description=description)
            metadata_path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
            return metadata

        return ProfileMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8"))

    def list_profiles(self) -> list[Any]:
        from authsome.auth.models.profile import ProfileMetadata

        profiles_dir = self._profiles_dir
        if not profiles_dir.exists():
            return []

        result = []
        for profile_dir in sorted(p for p in profiles_dir.iterdir() if p.is_dir()):
            metadata_path = profile_dir / "metadata.json"
            if metadata_path.exists():
                try:
                    result.append(ProfileMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8")))
                except Exception:
                    logger.warning("Skipping invalid profile: {}", profile_dir.name)
        return result

    def set_default_profile(self, name: str, home_path: Any) -> None:
        profile_dir = self._profiles_dir / name
        if not profile_dir.exists():
            raise ProfileNotFoundError(name)

        from authsome.auth.models.config import GlobalConfig

        config_path = home_path / "config.json"
        config = GlobalConfig()
        if config_path.exists():
            config = GlobalConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
        config.default_profile = name
        config_path.write_text(config.model_dump_json(indent=2), encoding="utf-8")

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
                except RefreshFailedError:
                    if now < record.expires_at:
                        return record.access_token
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
            record.status = ConnectionStatus.EXPIRED
            self._save_connection(record)
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
