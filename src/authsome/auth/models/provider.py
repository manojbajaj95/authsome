"""Provider definition models."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from authsome.auth.models.enums import AuthType, FlowType


class OAuthConfig(BaseModel):
    """OAuth2-specific provider configuration."""

    authorization_url: str
    token_url: str
    revocation_url: str | None = None
    device_authorization_url: str | None = None
    #: ``json`` = poll token URL with ``POST`` JSON body ``{"device_code": "..."}`` (e.g. Postiz CLI auth).
    device_token_request: Literal["oauth2_form", "json"] = "oauth2_form"
    scopes: list[str] = Field(default_factory=list)
    pkce: bool = True
    supports_device_flow: bool = False
    supports_dcr: bool = False
    registration_endpoint: str | None = None
    base_url: str | None = None

    model_config = {"extra": "allow"}


class ApiKeyConfig(BaseModel):
    """API key provider configuration."""

    header_name: str = "Authorization"
    header_prefix: str = "Bearer"

    model_config = {"extra": "allow"}


class ExportConfig(BaseModel):
    """Export mapping for environment variable names."""

    env: dict[str, str] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ProviderDefinition(BaseModel):
    """
    Complete provider definition.

    Stored as JSON in providers/<name>.json.
    """

    schema_version: int = 1
    name: str
    display_name: str
    auth_type: AuthType
    flow: FlowType

    oauth: OAuthConfig | None = None
    api_key: ApiKeyConfig | None = None
    export: ExportConfig | None = None
    docs: str | None = None
    host_url: str | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}

    def resolve_urls(self, base_url: str | None = None) -> ProviderDefinition:
        """Return a new ProviderDefinition with {base_url} templates resolved."""
        # Use provided base_url or fall back to the one in oauth config
        resolved_base_url = base_url or (self.oauth.base_url if self.oauth else None)
        if not resolved_base_url:
            return self

        # Create a copy
        resolved = self.model_copy(deep=True)

        def resolve(url: str | None) -> str | None:
            if url and "{base_url}" in url:
                return url.replace("{base_url}", resolved_base_url.rstrip("/"))
            return url

        # Resolve OAuth URLs
        if resolved.oauth:
            resolved.oauth.authorization_url = (
                resolve(resolved.oauth.authorization_url) or resolved.oauth.authorization_url
            )
            resolved.oauth.token_url = resolve(resolved.oauth.token_url) or resolved.oauth.token_url
            resolved.oauth.revocation_url = resolve(resolved.oauth.revocation_url)
            resolved.oauth.device_authorization_url = resolve(resolved.oauth.device_authorization_url)
            if resolved.oauth.registration_endpoint:
                resolved.oauth.registration_endpoint = resolve(resolved.oauth.registration_endpoint)

        # Resolve host_url if it contains the template
        resolved.host_url = resolve(resolved.host_url) or resolved.host_url

        return resolved
