"""Enumerations for auth types, flow types, connection statuses, and export formats."""

from enum import StrEnum


class AuthType(StrEnum):
    """Authentication mechanism used by a provider."""

    OAUTH2 = "oauth2"
    API_KEY = "api_key"


class FlowType(StrEnum):
    """Specific authentication flow for a provider."""

    PKCE = "pkce"
    DEVICE_CODE = "device_code"
    DCR_PKCE = "dcr_pkce"
    API_KEY = "api_key"


class ConnectionStatus(StrEnum):
    """Status of a credential connection."""

    NOT_CONNECTED = "not_connected"
    CONNECTED = "connected"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


class ExportFormat(StrEnum):
    """Supported credential export formats."""

    ENV = "env"
    SHELL = "shell"
    JSON = "json"
