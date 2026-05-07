"""
Authsome — A portable local authentication library for AI agents and developer tools.

Provides credential management for third-party services with support for:
- OAuth2 (PKCE, Device Code, DCR + PKCE)
- API key management
- Encrypted local storage (OS keyring or local file)

Usage:
    Run `authsome login openai` to start the local daemon and connect a
    provider, then use `authsome run ...` to inject credentials through the
    local proxy.
"""

from loguru import logger as _logger

from authsome.auth import AuthLayer, AuthService
from authsome.auth.models.connection import ConnectionRecord, Sensitive
from authsome.auth.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import (
    AuthenticationFailedError,
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    DiscoveryError,
    EncryptionUnavailableError,
    InputCancelledError,
    InvalidProviderSchemaError,
    ProfileNotFoundError,
    ProviderNotFoundError,
    RefreshFailedError,
    StoreUnavailableError,
    TokenExpiredError,
    UnsupportedAuthTypeError,
    UnsupportedFlowError,
)
from authsome.vault import Vault

_logger.disable("authsome")

__version__ = "0.2.3"

__all__ = [
    # Core
    "AuthLayer",
    "AuthService",
    "Vault",
    # Models
    "AuthType",
    "ConnectionRecord",
    "ConnectionStatus",
    "ExportFormat",
    "FlowType",
    "ProviderDefinition",
    "Sensitive",
    # Errors
    "AuthsomeError",
    "AuthenticationFailedError",
    "ConnectionNotFoundError",
    "CredentialMissingError",
    "DiscoveryError",
    "EncryptionUnavailableError",
    "InputCancelledError",
    "InvalidProviderSchemaError",
    "ProfileNotFoundError",
    "ProviderNotFoundError",
    "RefreshFailedError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnsupportedAuthTypeError",
    "UnsupportedFlowError",
]
