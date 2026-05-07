"""Connection routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from authsome.auth import AuthService
from authsome.auth.models.enums import ExportFormat
from authsome.server.routes._deps import get_auth_service

router = APIRouter(tags=["connections"])


@router.get("/connections")
def list_connections(auth: AuthService = Depends(get_auth_service)):
    by_source = auth.list_providers_by_source()
    return {
        "connections": auth.list_connections(),
        "by_source": {
            source: [provider.model_dump(mode="json") for provider in providers]
            for source, providers in by_source.items()
        },
    }


@router.get("/connections/{provider}/{connection}")
def get_connection(provider: str, connection: str, auth: AuthService = Depends(get_auth_service)):
    return auth.get_connection(provider, connection).model_dump(mode="json")


@router.post("/connections/{provider}/{connection}/logout")
def logout(provider: str, connection: str, auth: AuthService = Depends(get_auth_service)):
    auth.logout(provider, connection)
    return {"status": "ok"}


@router.post("/connections/{provider}/revoke")
def revoke(provider: str, auth: AuthService = Depends(get_auth_service)):
    auth.revoke(provider)
    return {"status": "ok"}


@router.post("/connections/{provider}/{connection}/default")
def set_default_connection(provider: str, connection: str, auth: AuthService = Depends(get_auth_service)):
    auth.set_default_connection(provider, connection)
    return {"status": "ok", "provider": provider, "default_connection": connection}


@router.post("/credentials/export")
def export_credentials(body: dict, auth: AuthService = Depends(get_auth_service)):
    provider = body.get("provider")
    connection = body.get("connection", "default")
    export_format = ExportFormat(body.get("format", "env"))
    return {"output": auth.export(provider, connection, format=export_format)}
