"""Provider definition models matching spec §9."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from authsome.models.enums import AuthType, FlowType


class OAuthConfig(BaseModel):
    """
    OAuth2-specific provider configuration.

    Spec §9.4: Required section for auth_type=oauth2.
    """

    authorization_url: str
    token_url: str
    revocation_url: str | None = None
    device_authorization_url: str | None = None
    scopes: list[str] = Field(default_factory=list)
    pkce: bool = True
    supports_device_flow: bool = False
    supports_dcr: bool = False
    registration_endpoint: str | None = None

    model_config = {"extra": "allow"}


class ApiKeyConfig(BaseModel):
    """
    API key provider configuration.

    Spec §9.4: Required section for auth_type=api_key.
    """

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

    Spec §9: Provider definitions stored as JSON in providers/<name>.json.
    Required top-level fields: schema_version, name, display_name, auth_type, flow.
    """

    schema_version: int = 1
    name: str
    display_name: str
    auth_type: AuthType
    flow: FlowType

    # Auth-type-specific sections
    oauth: OAuthConfig | None = None
    api_key: ApiKeyConfig | None = None

    # Export configuration
    export: ExportConfig | None = None

    # Forward-compatible
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}
