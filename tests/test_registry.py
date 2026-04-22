"""Tests for the provider registry."""

import json
from pathlib import Path

import pytest

from authsome.errors import InvalidProviderSchemaError, ProviderNotFoundError
from authsome.models.enums import AuthType, FlowType
from authsome.models.provider import (
    ApiKeyConfig,
    OAuthConfig,
    ProviderDefinition,
)
from authsome.providers.registry import ProviderRegistry


def _make_api_key_provider(name: str = "testprov") -> ProviderDefinition:
    return ProviderDefinition(
        name=name,
        display_name=f"Test {name}",
        auth_type=AuthType.API_KEY,
        flow=FlowType.API_KEY,
        api_key=ApiKeyConfig(),
    )


def _make_oauth_provider(name: str = "oauthprov") -> ProviderDefinition:
    return ProviderDefinition(
        name=name,
        display_name=f"OAuth {name}",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.DCR_PKCE,
        oauth=OAuthConfig(
            authorization_url="https://example.com/auth",
            token_url="https://example.com/token",
        ),
    )


class TestProviderRegistry:
    """Provider registry tests."""

    @pytest.fixture
    def registry(self, tmp_path: Path) -> ProviderRegistry:
        """Create a registry using a temp authsome home."""
        home = tmp_path / ".authsome"
        home.mkdir()
        (home / "providers").mkdir()
        return ProviderRegistry(home)

    def test_list_providers_empty(self, registry: ProviderRegistry) -> None:
        providers = registry.list_providers()
        # Should have bundled providers
        assert isinstance(providers, list)

    def test_list_providers_includes_bundled(self, registry: ProviderRegistry) -> None:
        providers = registry.list_providers()
        names = [p.name for p in providers]
        # Our bundled providers should be present
        assert "openai" in names
        assert "github" in names

    def test_get_bundled_provider(self, registry: ProviderRegistry) -> None:
        provider = registry.get_provider("openai")
        assert provider.name == "openai"
        assert provider.auth_type == AuthType.API_KEY

    def test_get_nonexistent_provider(self, registry: ProviderRegistry) -> None:
        with pytest.raises(ProviderNotFoundError):
            registry.get_provider("nonexistent-provider-xyz")

    def test_register_provider(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("myprov")
        registry.register_provider(provider)

        loaded = registry.get_provider("myprov")
        assert loaded.name == "myprov"
        assert loaded.display_name == "Test myprov"

    def test_register_duplicate_fails(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("dup")
        registry.register_provider(provider)

        with pytest.raises(FileExistsError):
            registry.register_provider(provider)

    def test_register_duplicate_force(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("dup2")
        registry.register_provider(provider)

        updated = _make_api_key_provider("dup2")
        updated.display_name = "Updated Name"
        registry.register_provider(updated, force=True)

        loaded = registry.get_provider("dup2")
        assert loaded.display_name == "Updated Name"

    def test_local_overrides_bundled(self, registry: ProviderRegistry) -> None:
        """Local provider file should override the bundled one."""
        custom_openai = ProviderDefinition(
            name="openai",
            display_name="Custom OpenAI",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(
                header_name="X-Custom",
                header_prefix="Key",
            ),
        )
        registry.register_provider(custom_openai, force=True)

        loaded = registry.get_provider("openai")
        assert loaded.display_name == "Custom OpenAI"
        assert loaded.api_key is not None
        assert loaded.api_key.header_name == "X-Custom"

    def test_list_providers_by_source_separates_custom(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("customsrc")
        registry.register_provider(provider)

        by_source = registry.list_providers_by_source()
        bundled_names = [p.name for p in by_source["bundled"]]
        custom_names = [p.name for p in by_source["custom"]]

        assert "customsrc" not in bundled_names
        assert "customsrc" in custom_names

    def test_invalid_local_provider_file_is_skipped(self, registry: ProviderRegistry) -> None:
        bad_path = registry._providers_dir / "bad.json"
        bad_path.write_text(json.dumps({"name": "bad", "display_name": 1}), encoding="utf-8")

        providers = registry.list_providers()
        names = [p.name for p in providers]
        assert "bad" not in names

    def test_validate_filesystem_unsafe_name(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("bad/name")
        with pytest.raises(InvalidProviderSchemaError, match="filesystem-safe"):
            registry.register_provider(provider)

    def test_validate_invalid_flow_for_auth_type(self, registry: ProviderRegistry) -> None:
        provider = ProviderDefinition(
            name="badflow",
            display_name="Bad Flow",
            auth_type=AuthType.API_KEY,
            flow=FlowType.DCR_PKCE,  # Invalid: DCR is for oauth2
            api_key=ApiKeyConfig(),
        )
        with pytest.raises(InvalidProviderSchemaError, match="not valid for auth_type"):
            registry.register_provider(provider)

    def test_validate_oauth_requires_oauth_section(self, registry: ProviderRegistry) -> None:
        provider = ProviderDefinition(
            name="nooauth",
            display_name="No OAuth",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            # Missing oauth section
        )
        with pytest.raises(InvalidProviderSchemaError, match="requires an 'oauth'"):
            registry.register_provider(provider)

    def test_validate_api_key_requires_api_key_section(self, registry: ProviderRegistry) -> None:
        provider = ProviderDefinition(
            name="noapikey",
            display_name="No API Key",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            # Missing api_key section
        )
        with pytest.raises(InvalidProviderSchemaError, match="requires an 'api_key'"):
            registry.register_provider(provider)

    def test_validate_oauth_url(self, registry: ProviderRegistry) -> None:
        provider = ProviderDefinition(
            name="badurl",
            display_name="Bad URL",
            auth_type=AuthType.OAUTH2,
            flow=FlowType.DCR_PKCE,
            oauth=OAuthConfig(
                authorization_url="not-a-url",
                token_url="https://example.com/token",
            ),
        )
        with pytest.raises(InvalidProviderSchemaError, match="Invalid URL"):
            registry.register_provider(provider)
