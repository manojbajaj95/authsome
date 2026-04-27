"""Provider discovery, resolution, and registration."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path
from urllib.parse import urlparse

from loguru import logger

from authsome.auth.models.enums import AuthType, FlowType
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import InvalidProviderSchemaError, ProviderNotFoundError
from authsome.utils import is_filesystem_safe

_VALID_FLOWS: dict[AuthType, set[FlowType]] = {
    AuthType.OAUTH2: {FlowType.PKCE, FlowType.DEVICE_CODE, FlowType.DCR_PKCE},
    AuthType.API_KEY: {FlowType.API_KEY},
}


class ProviderRegistry:
    """Resolves provider definitions from local files and bundled package data."""

    def __init__(self, providers_dir: Path) -> None:
        self._providers_dir = providers_dir

    @property
    def providers_dir(self) -> Path:
        return self._providers_dir

    def list_providers(self) -> list[ProviderDefinition]:
        providers: dict[str, ProviderDefinition] = {}
        for name, definition in self._load_bundled_providers().items():
            providers[name] = definition
        for name, definition in self._load_local_providers().items():
            providers[name] = definition
        return sorted(providers.values(), key=lambda p: p.name)

    def list_providers_by_source(self) -> dict[str, list[ProviderDefinition]]:
        bundled = self._load_bundled_providers()
        local = self._load_local_providers()
        bundled_list = sorted([v for k, v in bundled.items() if k not in local], key=lambda p: p.name)
        custom_list = sorted(local.values(), key=lambda p: p.name)
        return {"bundled": bundled_list, "custom": custom_list}

    def get_provider(self, name: str) -> ProviderDefinition:
        local_path = self._providers_dir / f"{name}.json"
        if local_path.exists():
            return self._load_provider_file(local_path)
        bundled = self._load_bundled_providers()
        if name in bundled:
            return bundled[name]
        raise ProviderNotFoundError(name)

    def register_provider(self, definition: ProviderDefinition, *, force: bool = False) -> None:
        self._validate_provider(definition)
        self._providers_dir.mkdir(parents=True, exist_ok=True)
        target = self._providers_dir / f"{definition.name}.json"
        if target.exists() and not force:
            raise FileExistsError(f"Provider '{definition.name}' already exists. Use force=True to overwrite.")
        target.write_text(definition.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
        logger.info("Registered provider: {} -> {}", definition.name, target)

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
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise InvalidProviderSchemaError(f"Invalid URL for '{field_name}': {url}", provider=provider_name)

    def _load_provider_file(self, path: Path) -> ProviderDefinition:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return ProviderDefinition.model_validate(data)
        except (json.JSONDecodeError, ValueError) as exc:
            raise InvalidProviderSchemaError(f"Failed to parse provider file {path}: {exc}") from exc

    def _load_local_providers(self) -> dict[str, ProviderDefinition]:
        providers: dict[str, ProviderDefinition] = {}
        if not self._providers_dir.exists():
            return providers
        for path in sorted(self._providers_dir.glob("*.json")):
            try:
                definition = self._load_provider_file(path)
                providers[definition.name] = definition
            except InvalidProviderSchemaError:
                logger.warning("Skipping invalid provider file: {}", path)
        return providers

    def _load_bundled_providers(self) -> dict[str, ProviderDefinition]:
        providers: dict[str, ProviderDefinition] = {}
        try:
            bundled_pkg = importlib.resources.files("authsome.auth.bundled_providers")
            for resource in bundled_pkg.iterdir():
                if resource.name.endswith(".json"):
                    try:
                        data = json.loads(resource.read_text(encoding="utf-8"))
                        definition = ProviderDefinition.model_validate(data)
                        providers[definition.name] = definition
                    except (json.JSONDecodeError, ValueError) as exc:
                        logger.warning("Skipping invalid bundled provider {}: {}", resource.name, exc)
        except (ModuleNotFoundError, FileNotFoundError):
            logger.debug("No bundled providers package found")
        return providers
