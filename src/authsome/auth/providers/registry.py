"""Provider discovery, resolution, and registration."""

from __future__ import annotations

import importlib.resources
import json
from urllib.parse import urlparse

from loguru import logger

from authsome.auth.models.enums import AuthType, FlowType
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import InvalidProviderSchemaError, ProviderNotFoundError
from authsome.store.local import LocalAppStore
from authsome.utils import is_filesystem_safe

_VALID_FLOWS: dict[AuthType, set[FlowType]] = {
    AuthType.OAUTH2: {FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE},
    AuthType.API_KEY: {FlowType.API_KEY},
}


def load_bundled_providers() -> dict[str, ProviderDefinition]:
    bundled = {}
    from authsome.auth.models.provider import ProviderDefinition

    try:
        files = importlib.resources.files("authsome.auth.bundled_providers")
        for file in files.iterdir():
            if file.name.endswith(".json"):
                with file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    definition = ProviderDefinition.model_validate(data)
                    bundled[definition.name] = definition
    except Exception as e:
        logger.warning(f"Error loading bundled providers: {e}")
    return bundled


class ProviderRegistry:
    """Resolves provider definitions from custom stores and bundled package data."""

    def __init__(self, app_store: LocalAppStore) -> None:
        """Initialize the registry with local custom provider persistence."""
        self._app_store = app_store
        self._bundled: dict[str, ProviderDefinition] = load_bundled_providers()

    def list_providers(self) -> list[ProviderDefinition]:
        providers = {**self._bundled, **self._load_local_providers()}
        return sorted(providers.values(), key=lambda p: p.name)

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        bundled_list = sorted([v for k, v in self._bundled.items()], key=lambda p: p.name)
        custom_list = sorted(self._load_local_providers().values(), key=lambda p: p.name)
        return {"bundled": bundled_list, "custom": custom_list}

    def is_local(self, name: str) -> bool:
        """Check if a provider is a custom/local provider."""
        try:
            self._app_store.get_provider(name)
            return True
        except ProviderNotFoundError:
            return False

    def get_provider(self, name: str) -> ProviderDefinition:
        try:
            return self._app_store.get_provider(name)
        except ProviderNotFoundError:
            if name in self._bundled:
                return self._bundled[name]
            raise ProviderNotFoundError(name)

    def register_provider(self, definition: ProviderDefinition, *, force: bool = False) -> None:
        self._validate_provider(definition)
        has_custom = True
        try:
            self._app_store.get_provider(definition.name)
        except ProviderNotFoundError:
            has_custom = False

        if force or not has_custom:
            self._app_store.save_provider(definition)
        else:
            raise FileExistsError(f"Provider '{definition.name}' already exists. Use force=True to overwrite.")
        logger.info("Registered provider: {}", definition.name)

    def _validate_provider(self, definition: ProviderDefinition) -> None:
        if not is_filesystem_safe(definition.name):
            raise InvalidProviderSchemaError(
                f"Provider name '{definition.name}' is not filesystem-safe", provider=definition.name
            )
        valid_flows = _VALID_FLOWS.get(definition.auth_type)
        if valid_flows is None:
            raise InvalidProviderSchemaError(
                f"Unrecognized auth_type: {definition.auth_type}", provider=definition.name
            )
        if definition.flow not in valid_flows:
            raise InvalidProviderSchemaError(
                f"Flow '{definition.flow}' is not valid for auth_type '{definition.auth_type}'. "
                f"Valid flows: {[f.value for f in valid_flows]}",
                provider=definition.name,
            )
        if definition.auth_type == AuthType.OAUTH2 and definition.oauth is None:
            raise InvalidProviderSchemaError(
                "auth_type 'oauth2' requires an 'oauth' configuration section", provider=definition.name
            )
        if definition.auth_type == AuthType.API_KEY and definition.api_key is None:
            raise InvalidProviderSchemaError(
                "auth_type 'api_key' requires an 'api_key' configuration section", provider=definition.name
            )
        if definition.oauth:
            for field_name in ("authorization_url", "token_url"):
                url = getattr(definition.oauth, field_name, None)
                if url:
                    self._validate_url(url, field_name, definition.name)

    @staticmethod
    def _validate_url(url: str, field_name: str, provider_name: str) -> None:
        if "{base_url}" in url:
            return
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise InvalidProviderSchemaError(f"Invalid URL for '{field_name}': {url}", provider=provider_name)

    def _load_local_providers(self) -> dict[str, ProviderDefinition]:
        providers = {}
        try:
            for p in self._app_store.list_providers():
                providers[p.name] = p
        except Exception as exc:
            logger.warning("Could not load custom providers: {}", exc)
        return providers

    def remove_provider(self, name: str) -> bool:
        """Remove a custom provider from the registry.

        Returns True if a provider was removed.
        """
        try:
            self._app_store.delete_provider(name)
            return True
        except ProviderNotFoundError:
            return False
