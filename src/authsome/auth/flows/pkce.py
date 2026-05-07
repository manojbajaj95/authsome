"""OAuth2 PKCE authorization code flow."""

from __future__ import annotations

import hashlib
import json
import secrets
import urllib.parse
from base64 import urlsafe_b64encode
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import requests as http_client

from authsome.auth.flows.base import AuthFlow, FlowResult
from authsome.auth.models.connection import AccountInfo, ConnectionRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import AuthenticationFailedError
from authsome.utils import utc_now

if TYPE_CHECKING:
    from authsome.auth.sessions import AuthSession

_CALLBACK_TIMEOUT_SECONDS = 300


def _generate_pkce() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class PkceFlow(AuthFlow):
    """OAuth2 PKCE authorization code flow."""

    callback_port: int = 7999

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
        if provider.oauth is None:
            raise AuthenticationFailedError("Provider missing 'oauth' configuration", provider=provider.name)
        if not client_id:
            raise AuthenticationFailedError("PKCE flow requires a client_id.", provider=provider.name)

        effective_scopes = scopes or provider.oauth.scopes or []
        code_verifier, code_challenge = _generate_pkce()

        # We assume the daemon or some orchestrator will handle the redirect
        # so we instruct the provider to redirect to the RuntimeServer callbacks endpoint.
        # But for now, we can just use localhost:7998
        redirect_uri = str(
            runtime_session.payload.get("callback_url_override", "http://127.0.0.1:7998/auth/callback/oauth")
        )

        state = secrets.token_urlsafe(32)
        auth_params: dict[str, str] = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if effective_scopes:
            auth_params["scope"] = " ".join(effective_scopes)

        auth_url = f"{provider.oauth.authorization_url}?{urllib.parse.urlencode(auth_params)}"

        runtime_session.state = "waiting_for_user"
        runtime_session.payload["auth_url"] = auth_url
        runtime_session.payload["callback_url"] = redirect_uri
        runtime_session.payload["internal_code_verifier"] = code_verifier
        runtime_session.payload["internal_state"] = state
        runtime_session.payload["internal_scopes"] = json.dumps(effective_scopes)

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
        if provider.oauth is None:
            raise AuthenticationFailedError("Provider missing 'oauth' configuration", provider=provider.name)
        if not client_id:
            raise AuthenticationFailedError("PKCE flow requires a client_id.", provider=provider.name)

        error = callback_data.get("error")
        if error:
            raise AuthenticationFailedError(f"OAuth error: {error}", provider=provider.name)

        auth_code = callback_data.get("code")
        if not auth_code:
            raise AuthenticationFailedError("Authorization timed out or no code received", provider=provider.name)

        returned_state = callback_data.get("state")
        expected_state = runtime_session.payload.get("internal_state")
        if returned_state != expected_state:
            raise AuthenticationFailedError("OAuth state mismatch — potential CSRF attack", provider=provider.name)

        code_verifier = runtime_session.payload.get("internal_code_verifier", "")
        redirect_uri = runtime_session.payload.get("callback_url", "")
        effective_scopes = json.loads(runtime_session.payload.get("internal_scopes", "[]"))

        token_data = self._exchange_code(
            provider=provider,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
        )

        runtime_session.state = "processing"

        now = utc_now()
        expires_in = token_data.get("expires_in")

        metadata: dict[str, str] = {"callback_handled_by": "runtime"}

        return FlowResult(
            connection=ConnectionRecord(
                schema_version=2,
                provider=provider.name,
                profile=profile,
                connection_name=connection_name,
                auth_type=AuthType.OAUTH2,
                status=ConnectionStatus.CONNECTED,
                scopes=effective_scopes,
                access_token=token_data.get("access_token", ""),
                refresh_token=token_data.get("refresh_token"),
                token_type=token_data.get("token_type", "Bearer"),
                expires_at=now + timedelta(seconds=int(expires_in)) if expires_in else None,
                obtained_at=now,
                account=AccountInfo(),
                metadata=metadata,
            )
        )

    @staticmethod
    def _exchange_code(
        *,
        provider: ProviderDefinition,
        auth_code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str | None,
        code_verifier: str,
    ) -> dict[str, Any]:
        assert provider.oauth is not None
        payload: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }
        if client_secret:
            payload["client_secret"] = client_secret

        try:
            resp = http_client.post(
                provider.oauth.token_url,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
        except http_client.RequestException as exc:
            raise AuthenticationFailedError(f"Token exchange failed: {exc}", provider=provider.name) from exc

        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError("Token response was not valid JSON", provider=provider.name) from exc

        if "access_token" not in data:
            error = data.get("error", "")
            error_desc = data.get("error_description", "Unknown error")
            raise AuthenticationFailedError(f"Token exchange error: {error} — {error_desc}", provider=provider.name)

        return data
