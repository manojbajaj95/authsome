"""API key authentication flow."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from authsome.auth.flows.base import AuthFlow, FlowResult
from authsome.auth.models.connection import AccountInfo, ConnectionRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import AuthenticationFailedError
from authsome.utils import utc_now

if TYPE_CHECKING:
    from authsome.auth.sessions import AuthSession


class ApiKeyFlow(AuthFlow):
    """Stores a user-provided API key as a connection record."""

    def begin(
        self,
        provider: ProviderDefinition,
        profile: str,
        connection_name: str,
        runtime_session: AuthSession,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        base_url: str | None = None,
    ) -> None:
        if provider.api_key is None:
            raise AuthenticationFailedError("Provider missing 'api_key' configuration", provider=provider.name)

        runtime_session.state = "waiting_for_user"
        runtime_session.payload["input_required"] = "api_key"

    def resume(
        self,
        provider: ProviderDefinition,
        profile: str,
        connection_name: str,
        runtime_session: AuthSession,
        callback_data: dict[str, Any],
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> FlowResult:
        if provider.api_key is None:
            raise AuthenticationFailedError("Provider missing 'api_key' configuration", provider=provider.name)

        api_key = runtime_session.payload.get("api_key")
        if not api_key or not str(api_key).strip():
            raise AuthenticationFailedError("API key cannot be empty", provider=provider.name)

        cleaned_key = api_key.strip()
        pattern = provider.api_key.key_pattern
        if pattern and re.fullmatch(pattern, cleaned_key) is None:
            hint = provider.api_key.key_pattern_hint or (
                f"API key for {provider.display_name} doesn't match the expected format."
            )
            raise AuthenticationFailedError(hint, provider=provider.name)

        runtime_session.state = "processing"
        return FlowResult(
            connection=ConnectionRecord(
                schema_version=2,  # TODO: Version should be somewhere else, like a global var
                provider=provider.name,
                profile=profile,
                connection_name=connection_name,
                auth_type=AuthType.API_KEY,
                status=ConnectionStatus.CONNECTED,
                api_key=cleaned_key,
                obtained_at=utc_now(),
                account=AccountInfo(),
                metadata={},
            )
        )
