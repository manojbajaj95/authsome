"""Provider discovery, resolution, and registration.

Spec §9.5: Provider resolution rules:
1. Look for providers/<name>.json in the local authsome home.
2. If not found, search built-in bundled providers.
3. If both exist, local file overrides built-in.

Spec §21: Registration validation requirements.
"""

from __future__ import annotations

import importlib.resources
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from authsome.errors import (
    InvalidProviderSchemaError,
    ProviderNotFoundError,
)
from authsome.models.enums import AuthType, FlowType
from authsome.models.provider import ProviderDefinition
from authsome.utils import is_filesystem_safe

logger = logging.getLogger(__name__)

# Valid flow types per auth type
_VALID_FLOWS: dict[AuthType, set[FlowType]] = {
    AuthType.OAUTH2: {FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE},
    AuthType.API_KEY: {FlowType.API_KEY_PROMPT, FlowType.API_KEY_ENV},
}


class ProviderRegistry:
    """
    Manages provider definitions from local files and bundled package data.

    Handles discovery, resolution, registration, and validation of provider
    definitions per spec §9.
    """

    def __init__(self, authsome_home: Path) -> None:
        """
        Initialize the provider registry.

        Args:
            authsome_home: The root authsome directory (e.g., ~/.authsome/).
        """
        self._authsome_home = authsome_home
        self._providers_dir = authsome_home / "providers"

    def list_providers(self) -> list[ProviderDefinition]:
        """
        List all available providers (local overrides + bundled).

        Local definitions take priority over bundled ones with the same name.

        Returns:
            List of all available provider definitions.
        """
        providers: dict[str, ProviderDefinition] = {}

        # Load bundled providers first
        for name, definition in self._load_bundled_providers().items():
            providers[name] = definition

        # Then overwrite with local providers (local takes priority per spec §9.5)
        for name, definition in self._load_local_providers().items():
            providers[name] = definition

        return sorted(providers.values(), key=lambda p: p.name)

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        """Return providers split into 'bundled' and 'custom' lists."""
        bundled = self._load_bundled_providers()
        local = self._load_local_providers()
        bundled_list = sorted(
            [v for k, v in bundled.items() if k not in local],
            key=lambda p: p.name,
        )
        custom_list = sorted(local.values(), key=lambda p: p.name)
        return {"bundled": bundled_list, "custom": custom_list}

    def get_provider(self, name: str) -> ProviderDefinition:
        """
        Get a provider by name.

        Resolution order (spec §9.5):
        1. Local providers/<name>.json
        2. Bundled provider fallback

        Args:
            name: Provider name (e.g., "github", "openai").

        Returns:
            The resolved ProviderDefinition.

        Raises:
            ProviderNotFoundError: If no provider with that name exists.
        """
        # Try local first
        local_path = self._providers_dir / f"{name}.json"
        if local_path.exists():
            return self._load_provider_file(local_path)

        # Try bundled
        bundled = self._load_bundled_providers()
        if name in bundled:
            return bundled[name]

        raise ProviderNotFoundError(name)

    def register_provider(
        self,
        definition: ProviderDefinition,
        *,
        force: bool = False,
    ) -> None:
        """
        Register a provider definition, writing it to providers/<name>.json.

        Spec §21: Validates required fields, filesystem-safe name, valid auth_type/flow combo.

        Args:
            definition: The provider definition to register.
            force: If True, overwrite an existing provider without error.

        Raises:
            InvalidProviderSchemaError: If validation fails.
            FileExistsError: If the provider exists and force is False.
        """
        self._validate_provider(definition)

        self._providers_dir.mkdir(parents=True, exist_ok=True)
        target = self._providers_dir / f"{definition.name}.json"

        if target.exists() and not force:
            raise FileExistsError(
                f"Provider '{definition.name}' already exists at {target}. Use force=True to overwrite."
            )

        target.write_text(
            definition.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )
        logger.info("Registered provider: %s -> %s", definition.name, target)

    def _validate_provider(self, definition: ProviderDefinition) -> None:
        """
        Validate a provider definition per spec §21.1.

        Checks:
        - Required fields exist (enforced by Pydantic)
        - name is filesystem-safe
        - auth_type is recognized
        - flow is valid for auth_type
        - URLs are syntactically valid where required
        """
        if not is_filesystem_safe(definition.name):
            raise InvalidProviderSchemaError(
                f"Provider name '{definition.name}' is not filesystem-safe",
                provider=definition.name,
            )

        # Validate flow is valid for auth type
        valid_flows = _VALID_FLOWS.get(definition.auth_type)
        if valid_flows is None:
            raise InvalidProviderSchemaError(
                f"Unrecognized auth_type: {definition.auth_type}",
                provider=definition.name,
            )
        if definition.flow not in valid_flows:
            raise InvalidProviderSchemaError(
                f"Flow '{definition.flow}' is not valid for auth_type '{definition.auth_type}'. "
                f"Valid flows: {[f.value for f in valid_flows]}",
                provider=definition.name,
            )

        # Validate auth-type-specific sections exist
        if definition.auth_type == AuthType.OAUTH2 and definition.oauth is None:
            raise InvalidProviderSchemaError(
                "auth_type 'oauth2' requires an 'oauth' configuration section",
                provider=definition.name,
            )
        if definition.auth_type == AuthType.API_KEY and definition.api_key is None:
            raise InvalidProviderSchemaError(
                "auth_type 'api_key' requires an 'api_key' configuration section",
                provider=definition.name,
            )

        # Validate URLs where required
        if definition.oauth:
            for field_name in ("authorization_url", "token_url"):
                url = getattr(definition.oauth, field_name, None)
                if url:
                    self._validate_url(url, field_name, definition.name)

    @staticmethod
    def _validate_url(url: str, field_name: str, provider_name: str) -> None:
        """Validate that a URL is syntactically valid."""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise InvalidProviderSchemaError(
                f"Invalid URL for '{field_name}': {url}",
                provider=provider_name,
            )

    def _load_provider_file(self, path: Path) -> ProviderDefinition:
        """Load and parse a single provider JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ProviderDefinition.model_validate(data)
        except (json.JSONDecodeError, ValueError) as exc:
            raise InvalidProviderSchemaError(f"Failed to parse provider file {path}: {exc}") from exc

    def _load_local_providers(self) -> dict[str, ProviderDefinition]:
        """Load all provider definitions from the local providers/ directory."""
        providers: dict[str, ProviderDefinition] = {}
        if not self._providers_dir.exists():
            return providers

        for path in sorted(self._providers_dir.glob("*.json")):
            try:
                definition = self._load_provider_file(path)
                providers[definition.name] = definition
            except InvalidProviderSchemaError:
                logger.warning("Skipping invalid provider file: %s", path)
        return providers

    def _load_bundled_providers(self) -> dict[str, ProviderDefinition]:
        """Load all bundled provider definitions from package data."""
        providers: dict[str, ProviderDefinition] = {}
        try:
            bundled_pkg = importlib.resources.files("authsome.bundled_providers")
            for resource in bundled_pkg.iterdir():
                if resource.name.endswith(".json"):
                    try:
                        data = json.loads(resource.read_text(encoding="utf-8"))
                        definition = ProviderDefinition.model_validate(data)
                        providers[definition.name] = definition
                    except (json.JSONDecodeError, ValueError) as exc:
                        logger.warning("Skipping invalid bundled provider %s: %s", resource.name, exc)
        except (ModuleNotFoundError, FileNotFoundError):
            logger.debug("No bundled providers package found")
        return providers
