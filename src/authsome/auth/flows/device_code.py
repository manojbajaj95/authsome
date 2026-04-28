"""OAuth2 Device Authorization Grant (RFC 8628)."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any

import requests
from loguru import logger

from authsome.auth.flows.base import AuthFlow, FlowResult
from authsome.auth.flows.bridge import DeviceCodeBridgeHandle, device_code_bridge
from authsome.auth.models.connection import AccountInfo, ConnectionRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import AuthenticationFailedError
from authsome.utils import utc_now

_DEFAULT_POLL_INTERVAL = 5
_MAX_POLL_DURATION = 900


class DeviceCodeFlow(AuthFlow):
    """OAuth2 Device Authorization Grant — headless flow."""

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
        if not provider.oauth.device_authorization_url:
            raise AuthenticationFailedError(
                "Provider does not have a device_authorization_url configured.", provider=provider.name
            )
        effective_scopes = list(scopes) if scopes is not None else list(provider.oauth.scopes or [])
        device_data = self._request_device_code(provider=provider, client_id=client_id, scopes=effective_scopes)

        device_code = device_data.get("device_code")
        user_code = device_data.get("user_code")
        verification_uri = device_data.get("verification_uri") or device_data.get("verification_url")
        verification_uri_complete = device_data.get("verification_uri_complete")
        expires_in = int(device_data.get("expires_in", _MAX_POLL_DURATION))
        interval = int(device_data.get("interval", _DEFAULT_POLL_INTERVAL))

        if not device_code or not user_code or not verification_uri:
            raise AuthenticationFailedError(
                "Device authorization response missing required fields", provider=provider.name
            )

        print(f"\n{'=' * 60}")
        print(f"  {provider.display_name} — Device Authorization")
        print(f"{'=' * 60}")
        print("\n  1. Open this URL in your browser:\n")
        print(f"     {verification_uri_complete or verification_uri}")
        print("\n  2. Enter this code when prompted:\n")
        print(f"     {user_code}")
        print(f"\n  Waiting for authorization (expires in {expires_in}s)...")
        print(f"{'=' * 60}\n")

        bridge: DeviceCodeBridgeHandle | None = None
        try:
            bridge = device_code_bridge(
                title=f"{provider.display_name} — Device Authorization",
                user_code=user_code,
                verification_uri=verification_uri,
                verification_uri_complete=verification_uri_complete,
            )
        except Exception as exc:
            # Bridge is best-effort; fall back to terminal output only.
            logger.warning("Device authorization browser bridge unavailable: {}", exc)

        try:
            token_data = self._poll_for_token(
                provider=provider,
                client_id=client_id,
                client_secret=client_secret,
                device_code=device_code,
                interval=interval,
                expires_in=expires_in,
            )
        finally:
            if bridge is not None:
                bridge.shutdown()

        now = utc_now()
        token_expires_in = token_data.get("expires_in")
        print(f"✓ Successfully authorized with {provider.display_name}!\n")

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
                expires_at=now + timedelta(seconds=int(token_expires_in)) if token_expires_in else None,
                obtained_at=now,
                account=AccountInfo(),
                metadata={},
            )
        )

    def _request_device_code(
        self, provider: ProviderDefinition, client_id: str | None, scopes: list[str]
    ) -> dict[str, Any]:
        assert provider.oauth is not None
        assert provider.oauth.device_authorization_url is not None
        payload: dict[str, str] = {}
        if client_id:
            payload["client_id"] = client_id
        if scopes:
            payload["scope"] = " ".join(scopes)
        try:
            resp = requests.post(
                provider.oauth.device_authorization_url,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=30,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise AuthenticationFailedError(
                f"Device authorization request failed: {exc}", provider=provider.name
            ) from exc
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError(
                "Device authorization response was not valid JSON", provider=provider.name
            ) from exc

    def _poll_for_token(
        self,
        provider: ProviderDefinition,
        client_id: str | None,
        client_secret: str | None,
        device_code: str,
        interval: int,
        expires_in: int,
    ) -> dict[str, Any]:
        assert provider.oauth is not None
        poll_interval = max(interval, 1)
        deadline = time.monotonic() + expires_in

        use_json = provider.oauth.device_token_request == "json"

        while time.monotonic() < deadline:
            time.sleep(poll_interval)

            try:
                if use_json:
                    resp = requests.post(
                        provider.oauth.token_url,
                        json={"device_code": device_code},
                        headers={"Accept": "application/json", "Content-Type": "application/json"},
                        timeout=30,
                    )
                else:
                    payload: dict[str, str] = {
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                    }
                    if client_id:
                        payload["client_id"] = client_id
                    if client_secret:
                        payload["client_secret"] = client_secret
                    resp = requests.post(
                        provider.oauth.token_url, data=payload, headers={"Accept": "application/json"}, timeout=30
                    )
            except requests.RequestException as exc:
                logger.warning("Token poll request failed: {}, retrying...", exc)
                continue

            try:
                data = resp.json()
            except json.JSONDecodeError:
                logger.warning("Token poll response was not JSON, retrying...")
                continue

            if resp.status_code == 200 and "access_token" in data:
                return data

            error = data.get("error", "")
            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                poll_interval += 5
            elif error == "access_denied":
                raise AuthenticationFailedError("User denied the authorization request", provider=provider.name)
            elif error == "expired_token":
                raise AuthenticationFailedError("Device code has expired. Please try again.", provider=provider.name)
            else:
                raise AuthenticationFailedError(
                    f"Token endpoint error: {data.get('error_description', error or 'Unknown error')}",
                    provider=provider.name,
                )

        raise AuthenticationFailedError("Device authorization timed out.", provider=provider.name)
