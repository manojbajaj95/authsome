"""Proxy support routes."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends

from authsome.auth import AuthService
from authsome.server.routes._deps import get_auth_service
from authsome.server.schemas import (
    CredentialResolutionRequest,
    CredentialResolutionResponse,
    ProviderRoute,
    ProxyRoutesResponse,
)

router = APIRouter(tags=["proxy"])


@router.get("/proxy/routes", response_model=ProxyRoutesResponse)
def proxy_routes(auth: AuthService = Depends(get_auth_service)) -> ProxyRoutesResponse:
    routes: list[ProviderRoute] = []
    for provider_group in auth.list_connections():
        provider_name = provider_group["name"]
        try:
            definition = auth.get_provider(provider_name)
        except Exception:
            continue
        if not definition.host_url:
            continue
        routes.append(
            ProviderRoute(
                provider=provider_name,
                connection=None,
                host_url=definition.host_url,
                auth_endpoint_paths=sorted(_auth_endpoint_paths(definition)),
            )
        )
    routes.sort(key=lambda route: (route.host_url.startswith("regex:"), route.provider))
    return ProxyRoutesResponse(routes=routes)


@router.post("/credentials/resolve", response_model=CredentialResolutionResponse)
def resolve_credentials(
    body: CredentialResolutionRequest,
    auth: AuthService = Depends(get_auth_service),
) -> CredentialResolutionResponse:
    connection = auth.resolve_connection_name(body.provider, body.connection)
    record = auth.get_connection(body.provider, connection)
    headers = auth.get_auth_headers(body.provider, connection)
    return CredentialResolutionResponse(
        provider=body.provider,
        connection=connection,
        headers=headers,
        expires_at=record.expires_at,
    )


def _auth_endpoint_paths(provider) -> set[str]:
    if not provider.oauth:
        return set()
    paths: set[str] = set()
    for raw_url in [
        provider.oauth.authorization_url,
        provider.oauth.token_url,
        provider.oauth.revocation_url,
        provider.oauth.device_authorization_url,
        provider.oauth.registration_endpoint,
    ]:
        if not raw_url:
            continue
        parsed = urlparse(raw_url)
        paths.add(parsed.path or "/")
    return paths
