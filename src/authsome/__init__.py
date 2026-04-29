"""
Authsome — A portable local authentication library for AI agents and developer tools.

Provides credential management for third-party services with support for:
- OAuth2 (PKCE, Device Code, DCR + PKCE)
- API key management
- Encrypted local storage (OS keyring or local file)

Usage:
    from authsome import AuthsomeContext

    ctx = AuthsomeContext.create()
    ctx.vault.init()
    ctx.auth.login("openai")
    headers = ctx.auth.get_auth_headers("openai")
"""

from loguru import logger as _logger

from authsome.auth import AuthLayer
from authsome.auth.models.connection import ConnectionRecord, Sensitive
from authsome.auth.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.auth.models.provider import ProviderDefinition
from authsome.context import AuthsomeContext
from authsome.errors import (
    AuthenticationFailedError,
    AuthsomeError,
    ConnectionNotFoundError,
    CredentialMissingError,
    DiscoveryError,
    EncryptionUnavailableError,
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

__version__ = "0.2.2"

__all__ = [
    # Core
    "AuthLayer",
    "AuthsomeContext",
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
    "InvalidProviderSchemaError",
    "ProfileNotFoundError",
    "ProviderNotFoundError",
    "RefreshFailedError",
    "StoreUnavailableError",
    "TokenExpiredError",
    "UnsupportedAuthTypeError",
    "UnsupportedFlowError",
]
