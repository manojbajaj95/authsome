"""DCR + PKCE OAuth2 authentication flow.

Spec §13.3: Dynamic Client Registration followed by PKCE authorization code flow.
Uses .well-known discovery for DCR endpoint when not explicitly configured.
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
from authsome.errors import AuthenticationFailedError, DiscoveryError
from authsome.flows.base import AuthFlow
from authsome.models.connection import AccountInfo, ConnectionRecord
from authsome.models.enums import AuthType, ConnectionStatus
from authsome.models.provider import ProviderDefinition
from authsome.utils import utc_now

logger = logging.getLogger(__name__)

_CALLBACK_TIMEOUT_SECONDS = 300  # 5 minute timeout for user to authorize


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
        """Send an HTML response."""
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP server logging."""
        logger.debug("Callback server: %s", format % args)


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _generate_pkce() -> tuple[str, str]:
    """
    Generate a PKCE code verifier and challenge.

    Returns:
        Tuple of (code_verifier, code_challenge).
    """
    # RFC 7636: 43-128 character unreserved URI string
    code_verifier = secrets.token_urlsafe(64)[:128]
    # S256: BASE64URL(SHA256(code_verifier))
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class DcrPkceFlow(AuthFlow):
    """
    Dynamic Client Registration + PKCE authorization code flow.

    Spec §13.3:
    1. Register client dynamically (or reuse existing).
    2. Store client metadata securely.
    3. Continue with PKCE flow.

    DCR registration endpoint is discovered via .well-known if not provided.
    """

    callback_port: int = 7999

    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        api_key: str | None = None,
    ) -> ConnectionRecord:
        """Execute the full DCR + PKCE flow."""
        if provider.oauth is None:
            raise AuthenticationFailedError(
                "Provider missing 'oauth' configuration",
                provider=provider.name,
            )

        effective_scopes = scopes or provider.oauth.scopes or []

        # --- Phase 1: Dynamic Client Registration ---
        if not client_id:
            client_id, client_secret = self._register_client(provider, effective_scopes)
        else:
            logger.info("Reusing existing client credentials for DCR flow")

        # --- Phase 2: PKCE Authorization ---
        code_verifier, code_challenge = _generate_pkce()

        # Start local callback server
        port = self.callback_port
        redirect_uri = f"http://127.0.0.1:{port}/callback"

        # Reset handler state
        _CallbackHandler.auth_code = None
        _CallbackHandler.error = None
        _CallbackHandler.state = None

        server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        try:
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
            logger.debug("Authorization URL: %s", auth_url)
            print(f"\nOpening browser for {provider.display_name} authorization...")
            print(f"If the browser doesn't open, visit:\n{auth_url}\n")
            webbrowser.open(auth_url)

            # Wait for callback
            server_thread.join(timeout=_CALLBACK_TIMEOUT_SECONDS)
        finally:
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

        # Validate state
        if _CallbackHandler.state != state:
            raise AuthenticationFailedError(
                "OAuth state mismatch — potential CSRF attack",
                provider=provider.name,
            )

        auth_code = _CallbackHandler.auth_code

        # --- Phase 3: Token Exchange ---
        token_data = self._exchange_code(
            provider=provider,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
        )

        # --- Phase 4: Build Connection Record ---
        now = utc_now()

        access_token = token_data.get("access_token", "")
        refresh_token_val = token_data.get("refresh_token")
        token_type = token_data.get("token_type", "Bearer")
        expires_in = token_data.get("expires_in")

        expires_at = None
        if expires_in:
            expires_at = now + timedelta(seconds=int(expires_in))

        encrypted_access = crypto.encrypt(access_token)
        encrypted_refresh = crypto.encrypt(refresh_token_val) if refresh_token_val else None
        encrypted_client_secret = crypto.encrypt(client_secret) if client_secret else None

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
            metadata={
                "_dcr_client_id": client_id,
                "_dcr_client_secret": (encrypted_client_secret.model_dump() if encrypted_client_secret else None),
            },
        )

    def _discover_registration_endpoint(self, provider: ProviderDefinition) -> str:
        """
        Discover the DCR registration endpoint via .well-known.

        Tries:
        1. OpenID Connect Discovery: <base>/.well-known/openid-configuration
        2. OAuth Server Metadata (RFC 8414): <base>/.well-known/oauth-authorization-server
        """
        if provider.oauth is None:
            raise DiscoveryError("No OAuth config", provider=provider.name)

        # Derive base URL from authorization_url
        parsed = urllib.parse.urlparse(provider.oauth.authorization_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Try OIDC discovery first
        discovery_urls = [
            f"{base_url}/.well-known/openid-configuration",
            f"{base_url}/.well-known/oauth-authorization-server",
        ]

        for url in discovery_urls:
            try:
                resp = http_client.get(url, timeout=15)
                if resp.status_code == 200:
                    metadata = resp.json()
                    reg_endpoint = metadata.get("registration_endpoint")
                    if reg_endpoint:
                        logger.info("Discovered registration endpoint: %s", reg_endpoint)
                        return reg_endpoint
            except (http_client.RequestException, json.JSONDecodeError) as exc:
                logger.debug("Discovery attempt failed for %s: %s", url, exc)
                continue

        raise DiscoveryError(
            "Could not discover registration_endpoint via .well-known. "
            "Set oauth.registration_endpoint in the provider definition.",
            provider=provider.name,
        )

    def _register_client(
        self,
        provider: ProviderDefinition,
        scopes: list[str],
    ) -> tuple[str, str | None]:
        """
        Perform Dynamic Client Registration.

        Returns:
            Tuple of (client_id, client_secret) — client_secret may be None for public clients.
        """
        if provider.oauth is None:
            raise AuthenticationFailedError("No OAuth config", provider=provider.name)

        # Determine registration endpoint
        reg_endpoint = provider.oauth.registration_endpoint
        if not reg_endpoint:
            reg_endpoint = self._discover_registration_endpoint(provider)

        # Build DCR request
        dcr_payload: dict[str, Any] = {
            "client_name": f"authsome-{provider.name}",
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        }

        if scopes:
            dcr_payload["scope"] = " ".join(scopes)

        # Add PKCE support indication
        dcr_payload["code_challenge_methods_supported"] = ["S256"]

        logger.info("Registering client via DCR at %s", reg_endpoint)

        try:
            resp = http_client.post(
                reg_endpoint,
                json=dcr_payload,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
        except http_client.RequestException as exc:
            raise AuthenticationFailedError(
                f"Dynamic Client Registration failed: {exc}",
                provider=provider.name,
            ) from exc

        try:
            reg_data = resp.json()
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError(
                "DCR response was not valid JSON",
                provider=provider.name,
            ) from exc

        client_id = reg_data.get("client_id")
        if not client_id:
            raise AuthenticationFailedError(
                "DCR response missing client_id",
                provider=provider.name,
            )

        client_secret = reg_data.get("client_secret")
        logger.info("DCR successful: client_id=%s", client_id)

        return client_id, client_secret

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
