"""Connection, provider metadata, and provider state record models matching spec §11-13."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from authsome.models.enums import AuthType, ConnectionStatus


class EncryptedField(BaseModel):
    """
    Portable encryption envelope for sensitive fields.

    Spec §10.4: AES-256-GCM encrypted field with base64-encoded components.
    """

    enc: int = 1
    alg: str = "AES-256-GCM"
    kid: str = "local"
    nonce: str  # base64-encoded
    ciphertext: str  # base64-encoded
    tag: str  # base64-encoded


class AccountInfo(BaseModel):
    """Account identity information from the provider."""

    id: str | None = None
    label: str | None = None


class ConnectionRecord(BaseModel):
    """
    Credential record for a named connection.

    Spec §12: Stored at key profile:<profile>:<provider>:connection:<connection_name>.
    Required fields: schema_version, provider, profile, connection_name, auth_type, status, metadata.
    """

    schema_version: int = 1
    provider: str
    profile: str
    connection_name: str
    auth_type: AuthType
    status: ConnectionStatus

    # OAuth2 fields
    scopes: list[str] | None = None
    access_token: EncryptedField | None = None
    refresh_token: EncryptedField | None = None
    token_type: str | None = None
    expires_at: datetime | None = None
    obtained_at: datetime | None = None

    # API key field
    api_key: EncryptedField | None = None

    # Account info
    account: AccountInfo | None = Field(default_factory=AccountInfo)

    # DCR-obtained client credentials (stored encrypted)
    client_id: str | None = None
    client_secret: EncryptedField | None = None

    # Forward-compatible metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}


class ProviderMetadataRecord(BaseModel):
    """
    Non-secret metadata about a provider within a profile.

    Spec §11: Stored at key profile:<profile>:<provider>:metadata.
    """

    schema_version: int = 1
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

    Spec §13: Stored at key profile:<profile>:<provider>:state.
    """

    schema_version: int = 1
    provider: str
    profile: str
    last_refresh_at: datetime | None = None
    last_refresh_error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "allow"}
