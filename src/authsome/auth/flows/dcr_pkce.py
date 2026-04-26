"""DCR + PKCE OAuth2 flow."""

from __future__ import annotations

import hashlib
import http.server
import json
import logging
import secrets
import threading
import urllib.parse
import webbrowser
from base64 import urlsafe_b64encode
from datetime import timedelta
from typing import Any

import requests as http_client

from authsome.auth.flows.base import AuthFlow, FlowResult
from authsome.auth.models.connection import AccountInfo, ConnectionRecord, ProviderClientRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import AuthenticationFailedError, DiscoveryError
from authsome.utils import utc_now

logger = logging.getLogger(__name__)

_CALLBACK_TIMEOUT_SECONDS = 300


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    auth_code: str | None = None
    error: str | None = None
    state: str | None = None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "error" in params:
            _CallbackHandler.error = params["error"][0]
            error_desc = params.get("error_description", [""])[0]
            self._send_response(400, f"<h1>Authentication Failed</h1><p>{_CallbackHandler.error}: {error_desc}</p>")
        elif "code" in params:
            _CallbackHandler.auth_code = params["code"][0]
            _CallbackHandler.state = params.get("state", [None])[0]
            self._send_response(200, "<h1>Authentication Successful</h1><p>You can close this window.</p>")
        else:
            self._send_response(400, "<h1>Invalid Callback</h1>")

    def _send_response(self, status: int, body: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Callback server: %s", format % args)


def _generate_pkce() -> tuple[str, str]:
    code_verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


class DcrPkceFlow(AuthFlow):
    """Dynamic Client Registration + PKCE authorization code flow."""

    callback_port: int = 7999

    def authenticate(
        self,
        provider: ProviderDefinition,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        api_key: str | None = None,
    ) -> FlowResult:
        if provider.oauth is None:
            raise AuthenticationFailedError("Provider missing 'oauth' configuration", provider=provider.name)

        effective_scopes = scopes or provider.oauth.scopes or []

        registered_new_client = not client_id
        if registered_new_client:
            client_id, client_secret = self._register_client(provider, effective_scopes)

        assert client_id is not None  # guaranteed: either passed in or registered above

        code_verifier, code_challenge = _generate_pkce()
        port = self.callback_port
        redirect_uri = f"http://127.0.0.1:{port}/callback"

        _CallbackHandler.auth_code = None
        _CallbackHandler.error = None
        _CallbackHandler.state = None

        server = http.server.HTTPServer(("127.0.0.1", port), _CallbackHandler)
        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()

        try:
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
            print(f"\nOpening browser for {provider.display_name} authorization...")
            print(f"If the browser doesn't open, visit:\n{auth_url}\n")
            webbrowser.open(auth_url)
            server_thread.join(timeout=_CALLBACK_TIMEOUT_SECONDS)
        finally:
            server.server_close()

        if _CallbackHandler.error:
            raise AuthenticationFailedError(f"OAuth error: {_CallbackHandler.error}", provider=provider.name)
        if not _CallbackHandler.auth_code:
            raise AuthenticationFailedError("Authorization timed out or no code received", provider=provider.name)
        if _CallbackHandler.state != state:
            raise AuthenticationFailedError("OAuth state mismatch — potential CSRF attack", provider=provider.name)

        token_data = self._exchange_code(
            provider=provider,
            auth_code=_CallbackHandler.auth_code,
            redirect_uri=redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=code_verifier,
        )

        now = utc_now()
        expires_in = token_data.get("expires_in")

        dcr_client = (
            ProviderClientRecord(
                schema_version=2,
                profile=profile,
                provider=provider.name,
                client_id=client_id,
                client_secret=client_secret,
            )
            if registered_new_client
            else None
        )
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
                metadata={},
            ),
            client_record=dcr_client,
        )

    def _discover_registration_endpoint(self, provider: ProviderDefinition) -> str:
        if provider.oauth is None:
            raise DiscoveryError("No OAuth config", provider=provider.name)
        parsed = urllib.parse.urlparse(provider.oauth.authorization_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        for url in [
            f"{base_url}/.well-known/openid-configuration",
            f"{base_url}/.well-known/oauth-authorization-server",
        ]:
            try:
                resp = http_client.get(url, timeout=15)
                if resp.status_code == 200:
                    reg_endpoint = resp.json().get("registration_endpoint")
                    if reg_endpoint:
                        return reg_endpoint
            except (http_client.RequestException, json.JSONDecodeError):
                continue
        raise DiscoveryError(
            "Could not discover registration_endpoint via .well-known. "
            "Set oauth.registration_endpoint in the provider definition.",
            provider=provider.name,
        )

    def _register_client(self, provider: ProviderDefinition, scopes: list[str]) -> tuple[str, str | None]:
        if provider.oauth is None:
            raise AuthenticationFailedError("No OAuth config", provider=provider.name)
        reg_endpoint = provider.oauth.registration_endpoint or self._discover_registration_endpoint(provider)
        dcr_payload: dict[str, Any] = {
            "client_name": f"authsome-{provider.name}",
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
            "code_challenge_methods_supported": ["S256"],
        }
        if scopes:
            dcr_payload["scope"] = " ".join(scopes)

        try:
            resp = http_client.post(
                reg_endpoint, json=dcr_payload, headers={"Content-Type": "application/json"}, timeout=30
            )
            resp.raise_for_status()
            reg_data = resp.json()
        except http_client.RequestException as exc:
            raise AuthenticationFailedError(
                f"Dynamic Client Registration failed: {exc}", provider=provider.name
            ) from exc
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError("DCR response was not valid JSON", provider=provider.name) from exc

        client_id = reg_data.get("client_id")
        if not client_id:
            raise AuthenticationFailedError("DCR response missing client_id", provider=provider.name)
        return client_id, reg_data.get("client_secret")

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
                provider.oauth.token_url, data=payload, headers={"Accept": "application/json"}, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
        except http_client.RequestException as exc:
            raise AuthenticationFailedError(f"Token exchange failed: {exc}", provider=provider.name) from exc
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError("Token response was not valid JSON", provider=provider.name) from exc

        if "access_token" not in data:
            raise AuthenticationFailedError(
                f"Token exchange error: {data.get('error', '')} — {data.get('error_description', 'Unknown error')}",
                provider=provider.name,
            )
        return data
