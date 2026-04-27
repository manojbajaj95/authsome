"""Tests for the provider registry."""

from pathlib import Path

import pytest

from authsome.auth.models.enums import AuthType, FlowType
from authsome.auth.models.provider import (
    ApiKeyConfig,
    OAuthConfig,
    ProviderDefinition,
)
from authsome.auth.providers.registry import ProviderRegistry
from authsome.errors import InvalidProviderSchemaError, ProviderNotFoundError


def _make_api_key_provider(name: str = "testprov") -> ProviderDefinition:
    return ProviderDefinition(
        name=name,
        display_name=f"Test {name}",
        auth_type=AuthType.API_KEY,
        flow=FlowType.API_KEY,
        api_key=ApiKeyConfig(env_var=f"{name.upper()}_KEY"),
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
        home = tmp_path / ".authsome"
        home.mkdir()
        providers_dir = home / "providers"
        providers_dir.mkdir()
        return ProviderRegistry(providers_dir)

    def test_list_providers_empty(self, registry: ProviderRegistry) -> None:
        registry.providers_dir.rmdir()
        providers = registry.list_providers()
        assert isinstance(providers, list)

    def test_list_providers_includes_bundled(self, registry: ProviderRegistry) -> None:
        providers = registry.list_providers()
        names = [p.name for p in providers]
        assert "openai" in names
        assert "github" in names

    def test_list_providers_by_source(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider("customprov")
        registry.register_provider(provider)

        sources = registry.list_providers_by_source()
        assert "bundled" in sources
        assert "custom" in sources
        assert any(p.name == "customprov" for p in sources["custom"])
        assert any(p.name == "openai" for p in sources["bundled"])

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
        custom_openai = ProviderDefinition(
            name="openai",
            display_name="Custom OpenAI",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
            api_key=ApiKeyConfig(
                header_name="X-Custom",
                header_prefix="Key",
                env_var="OPENAI_API_KEY",
            ),
        )
        registry.register_provider(custom_openai, force=True)

        loaded = registry.get_provider("openai")
        assert loaded.display_name == "Custom OpenAI"
        assert loaded.api_key is not None
        assert loaded.api_key.header_name == "X-Custom"

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
        )
        with pytest.raises(InvalidProviderSchemaError, match="requires an 'oauth'"):
            registry.register_provider(provider)

    def test_validate_api_key_requires_api_key_section(self, registry: ProviderRegistry) -> None:
        provider = ProviderDefinition(
            name="noapikey",
            display_name="No API Key",
            auth_type=AuthType.API_KEY,
            flow=FlowType.API_KEY,
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

    def test_register_oauth_provider(self, registry: ProviderRegistry) -> None:
        provider = _make_oauth_provider("goodoauth")
        registry.register_provider(provider)
        loaded = registry.get_provider("goodoauth")
        assert loaded.auth_type == AuthType.OAUTH2

    def test_validate_oauth_missing_optional_url(self, registry: ProviderRegistry) -> None:
        provider = _make_oauth_provider("opturl")
        provider.oauth.token_url = ""  # type: ignore
        registry.register_provider(provider)

    def test_list_providers_with_local(self, registry: ProviderRegistry) -> None:
        registry.register_provider(_make_api_key_provider("localprov"))
        providers = registry.list_providers()
        assert any(p.name == "localprov" for p in providers)

    def test_unrecognized_auth_type(self, registry: ProviderRegistry) -> None:
        provider = _make_api_key_provider()
        object.__setattr__(provider, "auth_type", "INVALID_TYPE")
        with pytest.raises(InvalidProviderSchemaError, match="Unrecognized auth_type"):
            registry._validate_provider(provider)

    def test_load_provider_file_error(self, registry: ProviderRegistry) -> None:
        registry.providers_dir.mkdir(parents=True, exist_ok=True)
        bad_file = registry.providers_dir / "bad.json"
        bad_file.write_text("invalid json")

        with pytest.raises(InvalidProviderSchemaError, match="Failed to parse provider file"):
            registry._load_provider_file(bad_file)

    def test_load_local_providers_error_skipping(self, registry: ProviderRegistry) -> None:
        registry.providers_dir.mkdir(parents=True, exist_ok=True)
        bad_file = registry.providers_dir / "bad.json"
        bad_file.write_text("invalid json")

        providers = registry._load_local_providers()
        assert "bad" not in providers

    def test_load_bundled_providers_errors(self, registry: ProviderRegistry, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib.resources

        def mock_files_error(*args, **kwargs):
            raise ModuleNotFoundError()

        monkeypatch.setattr(importlib.resources, "files", mock_files_error)
        assert registry._load_bundled_providers() == {}

        monkeypatch.undo()

        class MockResource:
            name = "bad.json"

            def read_text(self, *args, **kwargs):
                return "bad json"

        class MockPkg:
            def iterdir(self):
                return [MockResource()]

        def mock_files_success(*args, **kwargs):
            return MockPkg()

        monkeypatch.setattr(importlib.resources, "files", mock_files_success)
        assert registry._load_bundled_providers() == {}
