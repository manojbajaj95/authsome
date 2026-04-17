"""API key authentication flows.

Spec §13.4: API Key Prompt — prompt user for API key, validate, encrypt, store.
Spec §13.5: API Key Environment Import — read from environment variable, store.
"""

from __future__ import annotations

import getpass
import logging
import os

from authsome.crypto.base import CryptoBackend
from authsome.errors import AuthenticationFailedError, CredentialMissingError
from authsome.flows.base import AuthFlow
from authsome.models.connection import AccountInfo, ConnectionRecord
from authsome.models.enums import AuthType, ConnectionStatus
from authsome.models.provider import ProviderDefinition
from authsome.utils import utc_now

logger = logging.getLogger(__name__)


class ApiKeyPromptFlow(AuthFlow):
    """
    Interactive API key prompt flow.

    Spec §13.4:
    1. Prompt for API key securely.
    2. Validate non-empty input.
    3. Store encrypted key.
    4. Mark connection as connected.
    """

    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
    ) -> ConnectionRecord:
        """Prompt the user for an API key and create a connection record."""
        if provider.api_key is None:
            raise AuthenticationFailedError(
                "Provider missing 'api_key' configuration",
                provider=provider.name,
            )

        # Prompt securely
        prompt_text = f"Enter API key for {provider.display_name}: "
        try:
            api_key_value = getpass.getpass(prompt_text)
        except (EOFError, KeyboardInterrupt) as exc:
            raise AuthenticationFailedError(
                "API key input cancelled",
                provider=provider.name,
            ) from exc

        # Validate non-empty
        if not api_key_value.strip():
            raise AuthenticationFailedError(
                "API key cannot be empty",
                provider=provider.name,
            )

        api_key_value = api_key_value.strip()

        # Encrypt the key
        encrypted_key = crypto.encrypt(api_key_value)

        now = utc_now()
        return ConnectionRecord(
            schema_version=1,
            provider=provider.name,
            profile=profile,
            connection_name=connection_name,
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key=encrypted_key,
            obtained_at=now,
            account=AccountInfo(),
            metadata={},
        )


class ApiKeyEnvFlow(AuthFlow):
    """
    Environment variable API key import flow.

    Spec §13.5:
    1. Read expected environment variable from provider definition.
    2. If present, import into local store.
    3. Preserve normalized connection shape.
    """

    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
    ) -> ConnectionRecord:
        """Read an API key from environment and create a connection record."""
        if provider.api_key is None:
            raise AuthenticationFailedError(
                "Provider missing 'api_key' configuration",
                provider=provider.name,
            )

        env_var = provider.api_key.env_var
        if not env_var:
            raise AuthenticationFailedError(
                "Provider does not define an env_var for API key import",
                provider=provider.name,
            )

        api_key_value = os.environ.get(env_var)
        if not api_key_value:
            raise CredentialMissingError(
                f"Environment variable '{env_var}' is not set or empty",
                provider=provider.name,
            )

        # Encrypt the key
        encrypted_key = crypto.encrypt(api_key_value)

        now = utc_now()
        return ConnectionRecord(
            schema_version=1,
            provider=provider.name,
            profile=profile,
            connection_name=connection_name,
            auth_type=AuthType.API_KEY,
            status=ConnectionStatus.CONNECTED,
            api_key=encrypted_key,
            obtained_at=now,
            account=AccountInfo(),
            metadata={},
        )
