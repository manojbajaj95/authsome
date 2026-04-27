"""Tests for URL template resolution."""

from authsome.auth.models.enums import AuthType, FlowType
from authsome.auth.models.provider import OAuthConfig, ProviderDefinition


def test_url_template_resolution():
    provider = ProviderDefinition(
        name="github",
        display_name="GitHub",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            base_url="https://github.com",
            authorization_url="{base_url}/login/oauth/authorize",
            token_url="{base_url}/login/oauth/access_token",
            device_authorization_url="{base_url}/login/device/code",
        ),
        host_url="{base_url}/api/v3",
    )

    # Resolve with custom base URL
    resolved = provider.resolve_urls("https://github.acme.com")

    assert resolved.oauth.authorization_url == "https://github.acme.com/login/oauth/authorize"
    assert resolved.oauth.token_url == "https://github.acme.com/login/oauth/access_token"
    assert resolved.host_url == "https://github.acme.com/api/v3"

    # Resolve with no base URL override (should use base_url from oauth)
    resolved_default = provider.resolve_urls(None)
    assert resolved_default.oauth.authorization_url == "https://github.com/login/oauth/authorize"
    assert resolved_default.host_url == "https://github.com/api/v3"


def test_url_template_no_template():
    provider = ProviderDefinition(
        name="test",
        display_name="Test",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            authorization_url="https://example.com/auth",
            token_url="https://example.com/token",
        ),
    )

    # No base_url in oauth, and no base_url passed -> returns self
    resolved = provider.resolve_urls(None)
    assert resolved == provider

    # If base_url is passed but no templates in URLs, they remain unchanged
    resolved_with_base = provider.resolve_urls("https://other.com")
    assert resolved_with_base.oauth.authorization_url == "https://example.com/auth"


def test_url_template_trailing_slash():
    provider = ProviderDefinition(
        name="test",
        display_name="Test",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            authorization_url="{base_url}/auth",
            token_url="https://example.com/token",
        ),
    )

    resolved = provider.resolve_urls("https://other.com/")
    assert resolved.oauth.authorization_url == "https://other.com/auth"


def test_url_template_oauth_fields_direct():
    provider = ProviderDefinition(
        name="test",
        display_name="Test",
        auth_type=AuthType.OAUTH2,
        flow=FlowType.PKCE,
        oauth=OAuthConfig(
            base_url="https://default.com",
            authorization_url="{base_url}/authorize",
            token_url="{base_url}/token",
        ),
    )

    resolved = provider.resolve_urls("https://custom.com")
    assert resolved.oauth.authorization_url == "https://custom.com/authorize"
    assert resolved.oauth.token_url == "https://custom.com/token"
