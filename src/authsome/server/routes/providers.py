"""Provider routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from authsome.auth import AuthService
from authsome.auth.models.provider import ProviderDefinition
from authsome.server.routes._deps import get_auth_service

router = APIRouter(prefix="/providers", tags=["providers"])


@router.get("")
def list_providers(auth: AuthService = Depends(get_auth_service)):
    by_source = auth.list_providers_by_source()
    return {
        source: [provider.model_dump(mode="json") for provider in providers] for source, providers in by_source.items()
    }


@router.get("/{provider}")
def get_provider(provider: str, auth: AuthService = Depends(get_auth_service)):
    return auth.get_provider(provider).model_dump(mode="json")


@router.post("")
def register_provider(body: dict, auth: AuthService = Depends(get_auth_service)):
    definition_payload = body.get("definition", body)
    definition = ProviderDefinition.model_validate(definition_payload)
    auth.register_provider(definition, force=bool(body.get("force", False)))
    return {"status": "ok", "provider": definition.name}


@router.delete("/{provider}")
def delete_provider(provider: str, auth: AuthService = Depends(get_auth_service)):
    auth.remove(provider)
    return {"status": "ok", "provider": provider}
