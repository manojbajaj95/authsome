"""OAuth2 Device Authorization Grant (RFC 8628)."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import requests
from loguru import logger

from authsome.auth.flows.base import AuthFlow, FlowResult
from authsome.auth.models.connection import AccountInfo, ConnectionRecord
from authsome.auth.models.enums import AuthType, ConnectionStatus
from authsome.auth.models.provider import ProviderDefinition
from authsome.errors import AuthenticationFailedError
from authsome.utils import utc_now

if TYPE_CHECKING:
    from authsome.auth.sessions import AuthSession

_DEFAULT_POLL_INTERVAL = 5
_MAX_POLL_DURATION = 900


class DeviceCodeFlow(AuthFlow):
    """OAuth2 Device Authorization Grant — headless flow."""

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
        interval = int(device_data.get("interval", _DEFAULT_POLL_INTERVAL))
        expires_in = int(device_data.get("expires_in", _MAX_POLL_DURATION))

        if not device_code or not user_code or not verification_uri:
            raise AuthenticationFailedError(
                "Device authorization response missing required fields", provider=provider.name
            )

        runtime_session.state = "waiting_for_user"
        runtime_session.payload["user_code"] = user_code
        runtime_session.payload["verification_uri"] = verification_uri
        if verification_uri_complete:
            runtime_session.payload["verification_uri_complete"] = verification_uri_complete

        runtime_session.payload["internal_device_code"] = device_code
        runtime_session.payload["internal_interval"] = str(interval)
        runtime_session.payload["expires_in"] = str(expires_in)
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
    ) -> FlowResult | None:
        device_code = runtime_session.payload.get("internal_device_code")
        if not device_code:
            raise AuthenticationFailedError("No device_code available", provider=provider.name)

        interval = int(runtime_session.payload.get("internal_interval", 5))
        expires_in = int(runtime_session.payload.get("expires_in", 300))

        data = self.poll_for_token(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_code,
            interval=interval,
            expires_in=expires_in,
        )

        if "access_token" in data:
            now = utc_now()
            token_expires_in = data.get("expires_in")
            effective_scopes = json.loads(runtime_session.payload.get("internal_scopes", "[]"))
            runtime_session.state = "processing"

            return FlowResult(
                connection=ConnectionRecord(
                    schema_version=2,
                    provider=provider.name,
                    profile=profile,
                    connection_name=connection_name,
                    auth_type=AuthType.OAUTH2,
                    status=ConnectionStatus.CONNECTED,
                    scopes=effective_scopes,
                    access_token=data.get("access_token", ""),
                    refresh_token=data.get("refresh_token"),
                    token_type=data.get("token_type", "Bearer"),
                    expires_at=now + timedelta(seconds=int(token_expires_in)) if token_expires_in else None,
                    obtained_at=now,
                    account=AccountInfo(),
                    metadata={},
                )
            )

        error = data.get("error", "")
        if error == "authorization_pending":
            return None
        elif error == "slow_down":
            return None
        elif error == "access_denied":
            raise AuthenticationFailedError("User denied the authorization request", provider=provider.name)
        elif error == "expired_token":
            raise AuthenticationFailedError("Device code has expired. Please try again.", provider=provider.name)
        else:
            raise AuthenticationFailedError(
                f"Token endpoint error: {data.get('error_description', error or 'Unknown error')}",
                provider=provider.name,
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

    def poll_for_token(
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

        # Hard cap the polling at 300 seconds, regardless of provider's expires_in
        effective_expires_in = min(expires_in, 300)
        deadline = time.monotonic() + effective_expires_in

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
