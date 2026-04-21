"""AuthClient — the main entry point for the authsome SDK.

Implements all core operations from spec §19.1:
- Provider management (list, get, register)
- Connection management (list, get)
- Authentication (login)
- Token retrieval with auto-refresh (get_access_token, get_auth_headers)
- Lifecycle management (revoke, remove)
- Export (env, shell, json)
- Run (subprocess with injected credentials)
- Profile management
- Health checks (doctor)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any

import requests as http_client

from authsome.crypto.base import CryptoBackend
from authsome.crypto.keyring_crypto import KeyringCryptoBackend
from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
from authsome.errors import (
    ConnectionNotFoundError,
    CredentialMissingError,
    ProfileNotFoundError,
    RefreshFailedError,
    TokenExpiredError,
    UnsupportedFlowError,
)
from authsome.flows.api_key import ApiKeyFlow
from authsome.flows.base import AuthFlow
from authsome.flows.dcr_pkce import DcrPkceFlow
from authsome.flows.device_code import DeviceCodeFlow
from authsome.flows.pkce import PkceFlow
from authsome.models.config import GlobalConfig
from authsome.models.connection import (
    ConnectionRecord,
    ProviderClientRecord,
    ProviderMetadataRecord,
    ProviderStateRecord,
)
from authsome.models.enums import (
    AuthType,
    ConnectionStatus,
    ExportFormat,
    FlowType,
)
from authsome.models.profile import ProfileMetadata
from authsome.models.provider import ProviderDefinition
from authsome.providers.registry import ProviderRegistry
from authsome.store.base import CredentialStore
from authsome.store.sqlite_store import SQLiteStore
from authsome.utils import build_store_key, utc_now

logger = logging.getLogger(__name__)

# Spec §14.2: Recommended default refresh window
_NEAR_EXPIRY_SECONDS = 300

# Flow type → handler mapping
_FLOW_HANDLERS: dict[FlowType, type[AuthFlow]] = {
    FlowType.PKCE: PkceFlow,
    FlowType.DEVICE_CODE: DeviceCodeFlow,
    FlowType.DCR_PKCE: DcrPkceFlow,
    FlowType.API_KEY: ApiKeyFlow,
}


class AuthClient:
    """
    Main SDK entry point for credential management.

    Provides all library operations from spec §19.1.
    """

    def __init__(
        self,
        home: Path | None = None,
        profile: str | None = None,
    ) -> None:
        """
        Initialize the AuthClient.

        Args:
            home: Override the authsome home directory. Defaults to $AUTHSOME_HOME or ~/.authsome.
            profile: Override the active profile name. Defaults to config's default_profile.
        """
        # Resolve home directory
        env_home = os.environ.get("AUTHSOME_HOME")
        if home:
            self._home = Path(home)
        elif env_home:
            self._home = Path(env_home)
        else:
            self._home = Path.home() / ".authsome"

        self._profile_override = profile
        self._config: GlobalConfig | None = None
        self._crypto: CryptoBackend | None = None
        self._registry: ProviderRegistry | None = None
        self._stores: dict[str, CredentialStore] = {}

    @property
    def home(self) -> Path:
        """The resolved authsome home directory."""
        return self._home

    @property
    def config(self) -> GlobalConfig:
        """The global configuration, loading lazily."""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    @property
    def active_profile(self) -> str:
        """The currently active profile name."""
        return self._profile_override or self.config.default_profile

    @property
    def crypto(self) -> CryptoBackend:
        """The encryption backend, selected by config.encryption.mode."""
        if self._crypto is None:
            mode = self.config.encryption.mode if self.config.encryption else "local_key"
            if mode == "keyring":
                self._crypto = KeyringCryptoBackend()
            else:
                self._crypto = LocalFileCryptoBackend(self._home)
        return self._crypto

    @property
    def registry(self) -> ProviderRegistry:
        """The provider registry, initializing lazily."""
        if self._registry is None:
            self._registry = ProviderRegistry(self._home)
        return self._registry

    # ─── Initialization ───────────────────────────────────────────────────

    def init(self) -> None:
        """
        Initialize the authsome directory structure.

        Creates:
        - ~/.authsome/version
        - ~/.authsome/config.json
        - ~/.authsome/providers/
        - ~/.authsome/profiles/default/
        """
        self._home.mkdir(parents=True, exist_ok=True)

        # Write version file
        version_file = self._home / "version"
        if not version_file.exists():
            version_file.write_text("1\n", encoding="utf-8")

        # Write config.json
        config_file = self._home / "config.json"
        if not config_file.exists():
            config = GlobalConfig()
            config_file.write_text(
                config.model_dump_json(indent=2),
                encoding="utf-8",
            )

        # Create providers directory
        (self._home / "providers").mkdir(parents=True, exist_ok=True)

        # Create default profile
        self.create_profile("default", description="Default local profile")

        # Initialize crypto (generates master key if needed)
        _ = self.crypto

        logger.info("Initialized authsome at %s", self._home)

    # ─── Provider Operations ──────────────────────────────────────────────

    def list_providers(self) -> list[ProviderDefinition]:
        """List all available providers (local + bundled)."""
        return self.registry.list_providers()

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        """Return providers split into 'bundled' and 'custom' lists."""
        return self.registry.list_providers_by_source()

    def get_provider(self, name: str) -> ProviderDefinition:
        """Get a provider definition by name."""
        return self.registry.get_provider(name)

    def register_provider(
        self,
        definition: ProviderDefinition,
        *,
        force: bool = False,
    ) -> None:
        """Register or update a provider definition."""
        self.registry.register_provider(definition, force=force)

    # ─── Connection Operations ────────────────────────────────────────────

    def list_connections(
        self,
        profile: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        List all connections across all providers for a profile.

        Returns a list of dicts with provider name, status, auth_type, and connection names.
        """
        profile_name = profile or self.active_profile
        store = self._get_store(profile_name)

        # List all connection keys
        prefix = f"profile:{profile_name}:"
        keys = store.list_keys(prefix)

        # Group by provider
        providers: dict[str, list[dict[str, Any]]] = {}
        for key in keys:
            parts = key.split(":")
            if len(parts) >= 5 and parts[3] == "connection":
                provider_name = parts[2]
                connection_name = parts[4]

                record_json = store.get(key)
                if record_json:
                    record = ConnectionRecord.model_validate_json(record_json)
                    if provider_name not in providers:
                        providers[provider_name] = []
                    providers[provider_name].append(
                        {
                            "connection_name": connection_name,
                            "auth_type": record.auth_type.value,
                            "status": record.status.value,
                            "scopes": record.scopes,
                            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
                        }
                    )

        result = []
        for pname, connections in sorted(providers.items()):
            result.append(
                {
                    "name": pname,
                    "connections": connections,
                }
            )
        return result

    def get_connection(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> ConnectionRecord:
        """
        Get a specific connection record.

        Returns metadata by default (spec §16.3: safe defaults).
        """
        profile_name = profile or self.active_profile
        store = self._get_store(profile_name)

        key = build_store_key(
            profile=profile_name,
            provider=provider,
            record_type="connection",
            connection=connection,
        )

        record_json = store.get(key)
        if not record_json:
            raise ConnectionNotFoundError(
                provider=provider,
                connection=connection,
                profile=profile_name,
            )

        return ConnectionRecord.model_validate_json(record_json)

    # ─── Authentication ───────────────────────────────────────────────────

    def login(
        self,
        provider: str,
        connection_name: str = "default",
        scopes: list[str] | None = None,
        flow_override: FlowType | None = None,
        profile: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        api_key: str | None = None,
        force: bool = False,
    ) -> ConnectionRecord:
        """
        Authenticate with a provider using its configured flow.

        Args:
            provider: Provider name.
            connection_name: Connection name within the profile.
            scopes: Optional scope override.
            flow_override: Optional flow type override.
            profile: Optional profile override.
            client_id: Optional client ID override.
            client_secret: Optional client secret override.
            api_key: Optional API key override.

        Returns:
            The created ConnectionRecord.

        Raises:
            ProviderNotFoundError: If provider is not found.
            UnsupportedFlowError: If the flow is not implemented.
            AuthenticationFailedError: If authentication fails.
        """
        profile_name = profile or self.active_profile
        definition = self.get_provider(provider)

        flow_type = flow_override or definition.flow
        handler_cls = _FLOW_HANDLERS.get(flow_type)
        if handler_cls is None:
            raise UnsupportedFlowError(flow_type.value, provider=provider)

        handler = handler_cls()

        # Fetch or update client credentials
        client_record = self.get_provider_client_credentials(provider, profile_name)
        
        if client_id or client_secret:
            if client_record is not None and (client_record.client_id or client_record.client_secret):
                if not force:
                    raise AuthenticationFailedError(
                        "Client credentials already exist for this provider. Overriding them "
                        "may break existing connections. Use --force to proceed.",
                        provider=provider,
                    )
            
            if client_record is None:
                client_record = ProviderClientRecord(
                    profile=profile_name,
                    provider=provider,
                )
            if client_id is not None:
                client_record.client_id = client_id
            if client_secret is not None:
                client_record.client_secret = self.crypto.encrypt(client_secret)
            self._save_provider_client_credentials(client_record)

        flow_client_id = client_record.client_id if client_record else None
        flow_client_secret = self.crypto.decrypt(client_record.client_secret) if client_record and client_record.client_secret else None
        flow_api_key = api_key

        record = handler.authenticate(
            provider=definition,
            crypto=self.crypto,
            profile=profile_name,
            connection_name=connection_name,
            scopes=scopes,
            client_id=flow_client_id,
            client_secret=flow_client_secret,
            api_key=flow_api_key,
        )

        # For flows like DCR that generate client credentials and pass them via metadata
        if "_dcr_client_id" in record.metadata:
            if client_record is None:
                client_record = ProviderClientRecord(
                    profile=profile_name,
                    provider=provider,
                )
            client_record.client_id = record.metadata.pop("_dcr_client_id")
            
            dcr_secret_dict = record.metadata.pop("_dcr_client_secret", None)
            if dcr_secret_dict:
                from authsome.crypto.base import EncryptedField
                client_record.client_secret = EncryptedField(**dcr_secret_dict)
            else:
                client_record.client_secret = None
                
            self._save_provider_client_credentials(client_record)

        # Persist the connection record
        self._save_connection(record)

        # Update provider metadata record
        self._update_provider_metadata(
            profile=profile_name,
            provider=provider,
            connection_name=connection_name,
        )

        logger.info(
            "Login successful: provider=%s connection=%s profile=%s",
            provider,
            connection_name,
            profile_name,
        )
        return record

    # ─── Token Operations ─────────────────────────────────────────────────

    def get_access_token(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> str:
        """
        Get a usable access token, refreshing if needed.

        Spec §15 refresh semantics:
        1. If token is valid and not near expiry, return it.
        2. If expired or near expiry, attempt refresh.
        3. If refresh succeeds, update record.
        4. If refresh fails, set state and raise.

        Returns:
            The decrypted access token string.
        """
        profile_name = profile or self.active_profile
        record = self.get_connection(provider, connection, profile_name)

        if record.auth_type == AuthType.API_KEY:
            return self._get_api_key(record)

        if record.auth_type == AuthType.OAUTH2:
            return self._get_oauth_token(record, provider, connection, profile_name)

        raise CredentialMissingError(
            f"Unsupported auth type for token retrieval: {record.auth_type}",
            provider=provider,
        )

    def get_auth_headers(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> dict[str, str]:
        """
        Build authenticated request headers.

        Spec §20:
        - OAuth2: {"Authorization": "Bearer <access_token>"}
        - API key: Per provider config (header_name + header_prefix)
        """
        profile_name = profile or self.active_profile
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection, profile_name)

        if record.auth_type == AuthType.OAUTH2:
            token = self.get_access_token(provider, connection, profile_name)
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

        raise CredentialMissingError(
            f"Cannot build headers for auth type: {record.auth_type}",
            provider=provider,
        )

    # ─── Lifecycle Operations ─────────────────────────────────────────────

    def revoke(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> None:
        """
        Revoke credentials remotely (if supported) and remove locally.

        Spec §15.1:
        1. Attempt remote revocation if provider supports it.
        2. Remove/invalidate local credential material.
        3. Mark status as revoked or remove the record.
        """
        profile_name = profile or self.active_profile
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection, profile_name)

        # Attempt remote revocation for OAuth2
        if (
            record.auth_type == AuthType.OAUTH2
            and definition.oauth
            and definition.oauth.revocation_url
            and record.access_token
        ):
            try:
                token_value = self.crypto.decrypt(record.access_token)
                http_client.post(
                    definition.oauth.revocation_url,
                    data={"token": token_value},
                    timeout=15,
                )
                logger.info("Remote revocation sent for provider=%s", provider)
            except Exception as exc:
                logger.warning("Remote revocation failed (continuing): %s", exc)

        # Update record status to revoked
        record.status = ConnectionStatus.REVOKED
        record.access_token = None
        record.refresh_token = None
        record.api_key = None
        self._save_connection(record)

        logger.info("Revoked connection: provider=%s connection=%s", provider, connection)

    def remove(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
    ) -> None:
        """
        Remove local credential state without remote revocation.

        Spec §15.2: Delete local material only, no remote contact.
        """
        profile_name = profile or self.active_profile
        store = self._get_store(profile_name)

        key = build_store_key(
            profile=profile_name,
            provider=provider,
            record_type="connection",
            connection=connection,
        )

        deleted = store.delete(key)
        if not deleted:
            raise ConnectionNotFoundError(
                provider=provider,
                connection=connection,
                profile=profile_name,
            )

        # Update provider metadata
        self._remove_from_provider_metadata(profile_name, provider, connection)

        logger.info("Removed connection: provider=%s connection=%s", provider, connection)

    # ─── Export Operations ────────────────────────────────────────────────

    def export(
        self,
        provider: str,
        connection: str = "default",
        profile: str | None = None,
        format: ExportFormat = ExportFormat.ENV,
    ) -> str:
        """
        Export credentials in the specified format.

        Spec §16: Converts stored credentials into runtime-friendly output.
        """
        profile_name = profile or self.active_profile
        definition = self.get_provider(provider)
        record = self.get_connection(provider, connection, profile_name)

        # Gather export values
        values: dict[str, str] = {}
        export_map = definition.export.env if definition.export else {}

        if record.auth_type == AuthType.OAUTH2:
            if record.access_token:
                token = self.crypto.decrypt(record.access_token)
                env_name = export_map.get("access_token", f"{provider.upper()}_ACCESS_TOKEN")
                values[env_name] = token
            if record.refresh_token:
                refresh = self.crypto.decrypt(record.refresh_token)
                env_name = export_map.get("refresh_token", f"{provider.upper()}_REFRESH_TOKEN")
                values[env_name] = refresh

        elif record.auth_type == AuthType.API_KEY:
            if record.api_key:
                key = self.crypto.decrypt(record.api_key)
                env_name = export_map.get("api_key", f"{provider.upper()}_API_KEY")
                values[env_name] = key

        # Format output
        if format == ExportFormat.ENV:
            return "\n".join(f"{k}={v}" for k, v in values.items())
        elif format == ExportFormat.SHELL:
            return "\n".join(f"export {k}={v}" for k, v in values.items())
        elif format == ExportFormat.JSON:
            return json.dumps(values, indent=2)

        return ""

    # ─── Run Operations ───────────────────────────────────────────────────

    def run(
        self,
        command: list[str],
        providers: list[str] | None = None,
        profile: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Run a subprocess with injected exported credentials.

        Spec §23.2: Inject secrets into subprocess environment without logging.
        """
        profile_name = profile or self.active_profile
        env = os.environ.copy()

        for pname in providers or []:
            export_str = self.export(pname, profile=profile_name, format=ExportFormat.ENV)
            for line in export_str.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    env[key] = value
                    
        def _dquote(s: str) -> str:
            """Double-quote a token so $VAR references are expanded by the shell."""
            s = s.replace("\\", "\\\\")
            s = s.replace('"', '\\"')
            s = s.replace("`", "\\`")
            return f'"{s}"'

        shell_cmd = " ".join(_dquote(c) for c in command)
        return subprocess.run(
            shell_cmd,
            env=env,
            capture_output=False,
            text=True,
            check=False,
            shell=True,
        )

    # ─── Profile Operations ───────────────────────────────────────────────

    def create_profile(
        self,
        name: str,
        description: str | None = None,
    ) -> ProfileMetadata:
        """Create a new profile directory and metadata."""
        profile_dir = self._home / "profiles" / name
        profile_dir.mkdir(parents=True, exist_ok=True)

        metadata_path = profile_dir / "metadata.json"
        if not metadata_path.exists():
            now = utc_now()
            metadata = ProfileMetadata(
                name=name,
                created_at=now,
                updated_at=now,
                description=description,
            )
            metadata_path.write_text(
                metadata.model_dump_json(indent=2),
                encoding="utf-8",
            )
            return metadata

        return ProfileMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8"))

    def list_profiles(self) -> list[ProfileMetadata]:
        """List all local profiles."""
        profiles_dir = self._home / "profiles"
        if not profiles_dir.exists():
            return []

        result = []
        for profile_dir in sorted(profiles_dir.iterdir()):
            if profile_dir.is_dir():
                metadata_path = profile_dir / "metadata.json"
                if metadata_path.exists():
                    try:
                        metadata = ProfileMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8"))
                        result.append(metadata)
                    except Exception:
                        logger.warning("Skipping invalid profile: %s", profile_dir.name)
        return result

    def set_default_profile(self, name: str) -> None:
        """Set the global default profile."""
        profile_dir = self._home / "profiles" / name
        if not profile_dir.exists():
            raise ProfileNotFoundError(name)

        config = self.config
        config.default_profile = name
        config_path = self._home / "config.json"
        config_path.write_text(
            config.model_dump_json(indent=2),
            encoding="utf-8",
        )
        self._config = config

    # ─── Health Check ─────────────────────────────────────────────────────

    def doctor(self) -> dict[str, Any]:
        """
        Run health checks on directory layout, encryption, providers, store.

        Returns a dict with check results.
        """
        results: dict[str, Any] = {
            "home_exists": self._home.exists(),
            "version_file": (self._home / "version").exists(),
            "config_file": (self._home / "config.json").exists(),
            "providers_dir": (self._home / "providers").exists(),
            "profiles_dir": (self._home / "profiles").exists(),
            "encryption": False,
            "store": False,
            "providers_count": 0,
            "profiles_count": 0,
            "issues": [],
        }

        # Check encryption
        try:
            test_val = "doctor_test"
            encrypted = self.crypto.encrypt(test_val)
            decrypted = self.crypto.decrypt(encrypted)
            results["encryption"] = decrypted == test_val
        except Exception as exc:
            results["issues"].append(f"Encryption: {exc}")

        # Check store
        try:
            store = self._get_store(self.active_profile)
            store.set("__doctor_test__", "ok")
            val = store.get("__doctor_test__")
            store.delete("__doctor_test__")
            results["store"] = val == "ok"
        except Exception as exc:
            results["issues"].append(f"Store: {exc}")

        # Check providers
        try:
            providers = self.list_providers()
            results["providers_count"] = len(providers)
        except Exception as exc:
            results["issues"].append(f"Providers: {exc}")

        # Check profiles
        try:
            profiles = self.list_profiles()
            results["profiles_count"] = len(profiles)
        except Exception as exc:
            results["issues"].append(f"Profiles: {exc}")

        return results

    # ─── Internal Helpers ─────────────────────────────────────────────────

    def _load_config(self) -> GlobalConfig:
        """Load the global configuration from config.json."""
        config_path = self._home / "config.json"
        if config_path.exists():
            try:
                return GlobalConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to parse config.json, using defaults")
        return GlobalConfig()

    def _get_store(self, profile: str) -> CredentialStore:
        """Get or create a credential store for the given profile."""
        if profile not in self._stores:
            profile_dir = self._home / "profiles" / profile
            if not profile_dir.exists():
                raise ProfileNotFoundError(profile)
            self._stores[profile] = SQLiteStore(profile_dir)
        return self._stores[profile]

    def _save_connection(self, record: ConnectionRecord) -> None:
        """Persist a connection record to the store."""
        store = self._get_store(record.profile)
        key = build_store_key(
            profile=record.profile,
            provider=record.provider,
            record_type="connection",
            connection=record.connection_name,
        )
        store.set(key, record.model_dump_json())

    def get_provider_client_credentials(self, provider: str, profile: str) -> ProviderClientRecord | None:
        """Get the stored client credentials for a provider."""
        store = self._get_store(profile)
        key = build_store_key(
            profile=profile,
            provider=provider,
            record_type="client",
        )
        record_json = store.get(key)
        if record_json:
            return ProviderClientRecord.model_validate_json(record_json)
        return None

    def _save_provider_client_credentials(self, record: ProviderClientRecord) -> None:
        """Persist a provider client record to the store."""
        store = self._get_store(record.profile)
        key = build_store_key(
            profile=record.profile,
            provider=record.provider,
            record_type="client",
        )
        store.set(key, record.model_dump_json())

    def _update_provider_metadata(
        self,
        profile: str,
        provider: str,
        connection_name: str,
    ) -> None:
        """Update the provider metadata record after login."""
        store = self._get_store(profile)
        meta_key = build_store_key(
            profile=profile,
            provider=provider,
            record_type="metadata",
        )

        existing_json = store.get(meta_key)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
        else:
            metadata = ProviderMetadataRecord(
                profile=profile,
                provider=provider,
            )

        if connection_name not in metadata.connection_names:
            metadata.connection_names.append(connection_name)
        metadata.last_used_connection = connection_name
        store.set(meta_key, metadata.model_dump_json())

    def _remove_from_provider_metadata(
        self,
        profile: str,
        provider: str,
        connection_name: str,
    ) -> None:
        """Remove a connection from the provider metadata record."""
        store = self._get_store(profile)
        meta_key = build_store_key(
            profile=profile,
            provider=provider,
            record_type="metadata",
        )

        existing_json = store.get(meta_key)
        if existing_json:
            metadata = ProviderMetadataRecord.model_validate_json(existing_json)
            if connection_name in metadata.connection_names:
                metadata.connection_names.remove(connection_name)
            if metadata.last_used_connection == connection_name:
                metadata.last_used_connection = metadata.connection_names[0] if metadata.connection_names else None
            store.set(meta_key, metadata.model_dump_json())

    def _get_api_key(self, record: ConnectionRecord) -> str:
        """Decrypt and return the API key from a connection record."""
        if record.api_key is None:
            raise CredentialMissingError(
                "No API key stored in connection record",
                provider=record.provider,
            )
        return self.crypto.decrypt(record.api_key)

    def _get_oauth_token(
        self,
        record: ConnectionRecord,
        provider: str,
        connection: str,
        profile: str,
    ) -> str:
        """Get OAuth token with auto-refresh logic per spec §15."""
        if record.access_token is None:
            raise CredentialMissingError(
                "No access token stored",
                provider=provider,
            )

        # Check if token is still valid
        now = utc_now()
        if record.expires_at:
            near_expiry = record.expires_at - timedelta(seconds=_NEAR_EXPIRY_SECONDS)

            if now < near_expiry:
                # Token is valid and not near expiry
                return self.crypto.decrypt(record.access_token)

            # Token is expired or near expiry — attempt refresh
            if record.refresh_token:
                try:
                    refreshed = self._refresh_token(record, provider)
                    return self.crypto.decrypt(refreshed.access_token)  # type: ignore[arg-type]
                except RefreshFailedError:
                    # Check if the token hasn't actually expired yet
                    if now < record.expires_at:
                        return self.crypto.decrypt(record.access_token)
                    raise
            else:
                if now >= record.expires_at:
                    # Update status and raise
                    record.status = ConnectionStatus.EXPIRED
                    self._save_connection(record)
                    raise TokenExpiredError(provider=provider)
                # Still valid, just can't refresh
                return self.crypto.decrypt(record.access_token)
        else:
            # No expiry — token is perpetual
            return self.crypto.decrypt(record.access_token)

    def _refresh_token(
        self,
        record: ConnectionRecord,
        provider_name: str,
    ) -> ConnectionRecord:
        """
        Refresh an OAuth2 token.

        Spec §15:
        - On success, update the record.
        - On refreshable failure, remain expired.
        - On non-recoverable failure, transition to invalid.
        """
        definition = self.get_provider(provider_name)
        if definition.oauth is None:
            raise RefreshFailedError("No OAuth config", provider=provider_name)

        if record.refresh_token is None:
            raise RefreshFailedError("No refresh token available", provider=provider_name)

        refresh_token_value = self.crypto.decrypt(record.refresh_token)

        # Retrieve profile-level provider client credentials
        client_record = self.get_provider_client_credentials(provider_name, record.profile)
        client_id = None
        client_secret = None
        
        if client_record:
            client_id = client_record.client_id
            if client_record.client_secret:
                client_secret = self.crypto.decrypt(client_record.client_secret)

        if not client_id:
            raise RefreshFailedError("No client_id available for refresh", provider=provider_name)

        # Update provider state
        state_record = self._get_or_create_provider_state(record.profile, provider_name)

        # Direct POST for token refresh
        payload: dict[str, str] = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_value,
            "client_id": client_id,
        }
        if client_secret:
            payload["client_secret"] = client_secret

        try:
            resp = http_client.post(
                definition.oauth.token_url,
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

        # Success — update records
        now = utc_now()
        record.access_token = self.crypto.encrypt(token["access_token"])

        if "refresh_token" in token:
            record.refresh_token = self.crypto.encrypt(token["refresh_token"])

        if "expires_in" in token:
            record.expires_at = now + timedelta(seconds=int(token["expires_in"]))

        record.obtained_at = now
        record.status = ConnectionStatus.CONNECTED
        self._save_connection(record)

        state_record.last_refresh_at = now
        state_record.last_refresh_error = None
        self._save_provider_state(state_record)

        logger.info("Token refreshed: provider=%s", provider_name)
        return record

    def _get_or_create_provider_state(
        self,
        profile: str,
        provider: str,
    ) -> ProviderStateRecord:
        """Load or create a provider state record."""
        store = self._get_store(profile)
        key = build_store_key(profile=profile, provider=provider, record_type="state")
        existing = store.get(key)
        if existing:
            return ProviderStateRecord.model_validate_json(existing)
        return ProviderStateRecord(provider=provider, profile=profile)

    def _save_provider_state(self, state: ProviderStateRecord) -> None:
        """Persist a provider state record."""
        store = self._get_store(state.profile)
        key = build_store_key(
            profile=state.profile,
            provider=state.provider,
            record_type="state",
        )
        store.set(key, state.model_dump_json())

    def close(self) -> None:
        """Close all open stores."""
        for store in self._stores.values():
            store.close()
        self._stores.clear()

    def __enter__(self) -> AuthClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
