"""
Authsome — A portable local authentication library for AI agents and developer tools.

Provides credential management for third-party services with support for:
- OAuth2 (PKCE, Device Code, DCR + PKCE)
- API key management (prompt, env import)
- Encrypted local storage (OS keyring or local file)
- Cross-language compatible credential format

Usage:
    from authsome import AuthClient

    client = AuthClient()
    client.init()

    # Login to a provider
    client.login("openai")

    # Get auth headers for API calls
    headers = client.get_auth_headers("openai")

    # Export credentials
    env_vars = client.export("openai", format=ExportFormat.SHELL)
"""

from authsome.client import AuthClient
from authsome.crypto.base import CryptoBackend
from authsome.crypto.keyring_crypto import KeyringCryptoBackend
from authsome.crypto.local_file_crypto import LocalFileCryptoBackend
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
from authsome.models.connection import ConnectionRecord, EncryptedField
from authsome.models.enums import AuthType, ConnectionStatus, ExportFormat, FlowType
from authsome.models.provider import ProviderDefinition

__version__ = "0.1.2"

__all__ = [
    # Core
    "AuthClient",
    # Models
    "AuthType",
    "ConnectionStatus",
    "ExportFormat",
    "FlowType",
    "ProviderDefinition",
    "ConnectionRecord",
    "EncryptedField",
    # Crypto backends
    "CryptoBackend",
    "KeyringCryptoBackend",
    "LocalFileCryptoBackend",
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
