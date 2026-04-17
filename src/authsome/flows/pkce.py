"""OAuth2 PKCE authorization code flow (without DCR).

Spec §13.1: Used for browser-capable local environments with pre-registered clients.
Uses the client_id/client_secret from the provider definition's `client` section.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import secrets
import socket
import threading
import urllib.parse
import webbrowser
from base64 import urlsafe_b64encode
from datetime import timedelta
from typing import Any

import requests as http_client

from authsome.crypto.base import CryptoBackend
from authsome.errors import AuthenticationFailedError
from authsome.flows.base import AuthFlow
from authsome.models.connection import AccountInfo, ConnectionRecord
from authsome.models.enums import AuthType, ConnectionStatus
from authsome.models.provider import ProviderDefinition
from authsome.utils import utc_now

logger = logging.getLogger(__name__)

_CALLBACK_TIMEOUT_SECONDS = 300


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth callback authorization code."""

    auth_code: str | None = None
    error: str | None = None
    state: str | None = None

    def do_GET(self) -> None:
        """Handle the OAuth callback GET request."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            _CallbackHandler.error = params["error"][0]
            error_desc = params.get("error_description", [""])[0]
            self._send_response(
                400,
                f"<h1>Authentication Failed</h1><p>{_CallbackHandler.error}: {error_desc}</p>",
            )
        elif "code" in params:
            _CallbackHandler.auth_code = params["code"][0]
            _CallbackHandler.state = params.get("state", [None])[0]
            self._send_response(
                200,
                "<h1>Authentication Successful</h1><p>You can close this window and return to the terminal.</p>",
            )
        else:
            self._send_response(400, "<h1>Invalid Callback</h1><p>Missing authorization code.</p>")

    def _send_response(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Callback server: %s", format % args)


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _generate_pkce() -> tuple[str, str]:
    """Generate a PKCE code verifier and challenge (S256)."""
    code_verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class PkceFlow(AuthFlow):
    """
    OAuth2 PKCE authorization code flow (without DCR).

    Spec §13.1:
    1. Generate PKCE code verifier and challenge.
    2. Start a temporary localhost callback listener.
    3. Open authorization URL in the user's browser.
    4. Receive authorization code.
    5. Exchange code for token set.
    6. Persist normalized connection record.

    Requires pre-registered client credentials in the provider definition's
    `client` section (either literal or env:-prefixed).
    """

    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
    ) -> ConnectionRecord:
        """Execute the PKCE authorization code flow."""
        if provider.oauth is None:
            raise AuthenticationFailedError(
                "Provider missing 'oauth' configuration",
                provider=provider.name,
            )

        # Resolve client credentials from provider definition
        client_id: str | None = None
        client_secret: str | None = None

        if provider.client:
            client_id = provider.client.resolve_client_id()
            client_secret = provider.client.resolve_client_secret()

        if not client_id:
            raise AuthenticationFailedError(
                "PKCE flow requires a client_id in the provider's 'client' config "
                "(or set via the env: prefix). Use dcr_pkce flow for dynamic registration.",
                provider=provider.name,
            )

        effective_scopes = scopes or provider.oauth.scopes or []

        # --- PKCE ---
        code_verifier, code_challenge = _generate_pkce()

        # Start local callback server
        port = 7999
        redirect_uri = f"http://127.0.0.1:{port}/callback"

        # Reset handler state
        _CallbackHandler.auth_code = None
        _CallbackHandler.error = None
        _CallbackHandler.state = None

        server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        # Build authorization URL
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

        logger.info("Opening browser for authorization...")
        print(f"\nOpening browser for {provider.display_name} authorization...")
        print(f"If the browser doesn't open, visit:\n{auth_url}\n")
        webbrowser.open(auth_url)

        # Wait for callback
        server_thread.join(timeout=_CALLBACK_TIMEOUT_SECONDS)
        server.server_close()

        if _CallbackHandler.error:
            raise AuthenticationFailedError(
                f"OAuth error: {_CallbackHandler.error}",
                provider=provider.name,
            )

        if not _CallbackHandler.auth_code:
            raise AuthenticationFailedError(
                "Authorization timed out or no code received",
                provider=provider.name,
            )

        if _CallbackHandler.state != state:
            raise AuthenticationFailedError(
                "OAuth state mismatch — potential CSRF attack",
                provider=provider.name,
            )

        auth_code = _CallbackHandler.auth_code

        # --- Token Exchange ---
        token_data = self._exchange_code(
            provider=provider,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
        )

        # --- Build Connection Record ---
        now = utc_now()
        access_token_val = token_data.get("access_token", "")
        refresh_token_val = token_data.get("refresh_token")
        token_type = token_data.get("token_type", "Bearer")
        expires_in = token_data.get("expires_in")

        expires_at = None
        if expires_in:
            expires_at = now + timedelta(seconds=int(expires_in))

        encrypted_access = crypto.encrypt(access_token_val)
        encrypted_refresh = crypto.encrypt(refresh_token_val) if refresh_token_val else None

        return ConnectionRecord(
            schema_version=1,
            provider=provider.name,
            profile=profile,
            connection_name=connection_name,
            auth_type=AuthType.OAUTH2,
            status=ConnectionStatus.CONNECTED,
            scopes=effective_scopes,
            access_token=encrypted_access,
            refresh_token=encrypted_refresh,
            token_type=token_type,
            expires_at=expires_at,
            obtained_at=now,
            account=AccountInfo(),
            metadata={},
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
        """Exchange an authorization code for tokens via direct POST."""
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
            raise AuthenticationFailedError(
                f"Token exchange failed: {exc}",
                provider=provider.name,
            ) from exc

        try:
            data = resp.json()
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError(
                "Token response was not valid JSON",
                provider=provider.name,
            ) from exc

        if "access_token" not in data:
            error = data.get("error", "")
            error_desc = data.get("error_description", "Unknown error")
            raise AuthenticationFailedError(
                f"Token exchange error: {error} — {error_desc}",
                provider=provider.name,
            )

        return data
