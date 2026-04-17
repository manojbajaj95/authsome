"""OAuth2 Device Code flow.

Spec §13.2: Used for headless or remote environments.
1. Request device code from device_authorization_url.
2. Display verification URL and user code.
3. Poll token endpoint according to provider rules.
4. Persist normalized connection record.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import timedelta
from typing import Any

import requests

from authsome.crypto.base import CryptoBackend
from authsome.errors import AuthenticationFailedError
from authsome.flows.base import AuthFlow
from authsome.models.connection import AccountInfo, ConnectionRecord
from authsome.models.enums import AuthType, ConnectionStatus
from authsome.models.provider import ProviderDefinition
from authsome.utils import utc_now

logger = logging.getLogger(__name__)

# Default polling interval if not specified by the server
_DEFAULT_POLL_INTERVAL = 5
# Maximum time to wait for user to authorize
_MAX_POLL_DURATION = 900  # 15 minutes


class DeviceCodeFlow(AuthFlow):
    """
    OAuth2 Device Authorization Grant (RFC 8628).

    Spec §13.2:
    1. Request device code from the provider's device_authorization_url.
    2. Display verification URL and user code to the user.
    3. Poll the token endpoint at the specified interval.
    4. On success, persist normalized connection record.

    Requires:
    - Provider's `oauth.device_authorization_url` to be set.
    - Client credentials in the provider's `client` section.
    """

    def authenticate(
        self,
        provider: ProviderDefinition,
        crypto: CryptoBackend,
        profile: str,
        connection_name: str,
        scopes: list[str] | None = None,
    ) -> ConnectionRecord:
        """Execute the device code authorization flow."""
        if provider.oauth is None:
            raise AuthenticationFailedError(
                "Provider missing 'oauth' configuration",
                provider=provider.name,
            )

        if not provider.oauth.device_authorization_url:
            raise AuthenticationFailedError(
                "Provider does not have a device_authorization_url configured. "
                "Device code flow is not supported for this provider.",
                provider=provider.name,
            )

        # Resolve client credentials
        client_id: str | None = None
        client_secret: str | None = None

        if provider.client:
            client_id = provider.client.resolve_client_id()
            client_secret = provider.client.resolve_client_secret()

        if not client_id:
            raise AuthenticationFailedError(
                "Device code flow requires a client_id in the provider's 'client' config.",
                provider=provider.name,
            )

        effective_scopes = scopes or provider.oauth.scopes or []

        # --- Phase 1: Request Device Code ---
        device_data = self._request_device_code(
            provider=provider,
            client_id=client_id,
            scopes=effective_scopes,
        )

        device_code = device_data.get("device_code")
        user_code = device_data.get("user_code")
        verification_uri = device_data.get("verification_uri") or device_data.get("verification_url")
        verification_uri_complete = device_data.get("verification_uri_complete")
        expires_in = int(device_data.get("expires_in", _MAX_POLL_DURATION))
        interval = int(device_data.get("interval", _DEFAULT_POLL_INTERVAL))

        if not device_code or not user_code or not verification_uri:
            raise AuthenticationFailedError(
                "Device authorization response missing required fields (device_code, user_code, verification_uri)",
                provider=provider.name,
            )

        # --- Phase 2: Display Instructions ---
        print(f"\n{'=' * 60}")
        print(f"  {provider.display_name} — Device Authorization")
        print(f"{'=' * 60}")
        print("\n  1. Open this URL in your browser:\n")
        if verification_uri_complete:
            print(f"     {verification_uri_complete}")
        else:
            print(f"     {verification_uri}")
        print("\n  2. Enter this code when prompted:\n")
        print(f"     {user_code}")
        print(f"\n  Waiting for authorization (expires in {expires_in}s)...")
        print(f"{'=' * 60}\n")

        # --- Phase 3: Poll Token Endpoint ---
        token_data = self._poll_for_token(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            device_code=device_code,
            interval=interval,
            expires_in=expires_in,
        )

        # --- Phase 4: Build Connection Record ---
        now = utc_now()
        access_token_val = token_data.get("access_token", "")
        refresh_token_val = token_data.get("refresh_token")
        token_type = token_data.get("token_type", "Bearer")
        token_expires_in = token_data.get("expires_in")

        expires_at = None
        if token_expires_in:
            expires_at = now + timedelta(seconds=int(token_expires_in))

        encrypted_access = crypto.encrypt(access_token_val)
        encrypted_refresh = crypto.encrypt(refresh_token_val) if refresh_token_val else None

        print(f"✓ Successfully authorized with {provider.display_name}!\n")

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

    def _request_device_code(
        self,
        provider: ProviderDefinition,
        client_id: str,
        scopes: list[str],
    ) -> dict[str, Any]:
        """Request a device code from the provider's device authorization endpoint."""
        assert provider.oauth is not None
        assert provider.oauth.device_authorization_url is not None

        payload: dict[str, str] = {
            "client_id": client_id,
        }
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
        except requests.RequestException as exc:
            raise AuthenticationFailedError(
                f"Device authorization request failed: {exc}",
                provider=provider.name,
            ) from exc

        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise AuthenticationFailedError(
                "Device authorization response was not valid JSON",
                provider=provider.name,
            ) from exc

    def _poll_for_token(
        self,
        provider: ProviderDefinition,
        client_id: str,
        client_secret: str | None,
        device_code: str,
        interval: int,
        expires_in: int,
    ) -> dict[str, Any]:
        """
        Poll the token endpoint until authorization completes, expires, or is denied.

        Handles:
        - authorization_pending: continue polling
        - slow_down: increase interval by 5 seconds (per RFC 8628)
        - access_denied: user denied, raise error
        - expired_token: device code expired, raise error
        """
        assert provider.oauth is not None

        poll_interval = max(interval, 1)  # At least 1 second
        deadline = time.monotonic() + expires_in

        while time.monotonic() < deadline:
            time.sleep(poll_interval)

            payload: dict[str, str] = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
            if client_secret:
                payload["client_secret"] = client_secret

            try:
                resp = requests.post(
                    provider.oauth.token_url,
                    data=payload,
                    headers={"Accept": "application/json"},
                    timeout=30,
                )
            except requests.RequestException as exc:
                logger.warning("Token poll request failed: %s, retrying...", exc)
                continue

            try:
                data = resp.json()
            except json.JSONDecodeError:
                logger.warning("Token poll response was not JSON, retrying...")
                continue

            # Successful token response
            if resp.status_code == 200 and "access_token" in data:
                return data

            error = data.get("error", "")

            if error == "authorization_pending":
                # User hasn't authorized yet — keep polling
                logger.debug("Authorization pending, polling again in %ds...", poll_interval)
                continue

            elif error == "slow_down":
                # RFC 8628 §3.5: increase interval by 5 seconds
                poll_interval += 5
                logger.debug("Slow down requested, new interval: %ds", poll_interval)
                continue

            elif error == "access_denied":
                raise AuthenticationFailedError(
                    "User denied the authorization request",
                    provider=provider.name,
                )

            elif error == "expired_token":
                raise AuthenticationFailedError(
                    "Device code has expired. Please try again.",
                    provider=provider.name,
                )

            else:
                error_desc = data.get("error_description", error or "Unknown error")
                raise AuthenticationFailedError(
                    f"Token endpoint error: {error_desc}",
                    provider=provider.name,
                )

        raise AuthenticationFailedError(
            "Device authorization timed out. Please try again.",
            provider=provider.name,
        )
