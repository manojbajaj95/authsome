"""Connection, provider metadata, and provider state record models (v2).

Schema version 2: tokens are stored as plaintext strings.
Encryption is handled entirely by the Vault at the record level.
Sensitive fields are marked with Annotated[..., Sensitive()] so callers
can redact them before display without knowing field names in advance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, Field

from authsome.auth.models.enums import AuthType, ConnectionStatus


class Sensitive:
    """Marker annotation: field contains a secret that must be redacted before display."""


class AccountInfo(BaseModel):
    """Account identity information returned by the provider."""

    id: str | None = None
    label: str | None = None


class ConnectionRecord(BaseModel):
    """
    Credential record for a named connection (schema v2).

    Stored at key: profile:<identity>:<provider>:connection:<name>
    All sensitive fields are plaintext — encryption is at vault level.
    """

    schema_version: int = 2
    provider: str
    profile: str
    connection_name: str
    auth_type: AuthType
    status: ConnectionStatus
    base_url: str | None = None
    host_url: str | None = None

    # OAuth2 fields
    scopes: list[str] | None = None
    access_token: Annotated[str | None, Sensitive()] = None
    refresh_token: Annotated[str | None, Sensitive()] = None
    token_type: str | None = None
    expires_at: datetime | None = None
    obtained_at: datetime | None = None

    # API key field
    api_key: Annotated[str | None, Sensitive()] = None

    # Account info
    account: AccountInfo | None = Field(default_factory=AccountInfo)

    # Forward-compatible metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ProviderMetadataRecord(BaseModel):
    """
    Non-secret metadata about a provider within a profile.

    Stored at key: profile:<identity>:<provider>:metadata
    """

    schema_version: int = 2
    profile: str
    provider: str
    default_connection: str = "default"
    connection_names: list[str] = Field(default_factory=list)
    last_used_connection: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ProviderStateRecord(BaseModel):
    """
    Transient, non-secret provider state within a profile.

    Stored at key: profile:<identity>:<provider>:state
    """

    schema_version: int = 2
    provider: str
    profile: str
    last_refresh_at: datetime | None = None
    last_refresh_error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ProviderClientRecord(BaseModel):
    """
    Client credentials configured for a provider within a profile.

    Stored at key: profile:<identity>:<provider>:client
    """

    schema_version: int = 2
    profile: str
    provider: str
    client_id: str | None = None
    client_secret: Annotated[str | None, Sensitive()] = None
    base_url: str | None = None
    host_url: str | None = None
    scopes: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}
