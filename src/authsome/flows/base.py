"""Abstract base class for authentication flows."""

from __future__ import annotations

from abc import ABC, abstractmethod

from authsome.crypto.base import CryptoBackend
from authsome.models.connection import ConnectionRecord
from authsome.models.provider import ProviderDefinition


class AuthFlow(ABC):
    """
    Abstract authentication flow handler.

    Each flow implementation handles a specific authentication mechanism
    (e.g., DCR+PKCE, API key prompt) and produces a ConnectionRecord.
    """

    @abstractmethod
    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
    ) -> ConnectionRecord:
        """
        Execute the authentication flow and return a connection record.

        Args:
            provider: The provider definition to authenticate against.
            crypto: Encryption backend for securing credentials.
            profile: The profile name to associate the connection with.
            connection_name: The connection name within the profile.
            scopes: Optional override for requested scopes.

        Returns:
            A ConnectionRecord with encrypted credential fields.

        Raises:
            AuthenticationFailedError: If the flow fails.
        """
        ...
