"""FastAPI app factory for the Authsome daemon."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from authsome.auth.sessions import AuthSessionStore
from authsome.errors import AuthsomeError
from authsome.server.dependencies import create_auth_service
from authsome.server.routes.auth import router as auth_router
from authsome.server.routes.connections import router as connections_router
from authsome.server.routes.health import router as health_router
from authsome.server.routes.providers import router as providers_router
from authsome.server.routes.proxy import router as proxy_router


def create_app(auth_service=None) -> FastAPI:
    """Create the local daemon FastAPI app."""
    app = FastAPI(title="Authsome Daemon", version="0.1")
    app.state.auth_service = auth_service or create_auth_service()
    app.state.auth_sessions = AuthSessionStore()

    @app.exception_handler(AuthsomeError)
    def authsome_error_handler(request: Request, exc: AuthsomeError) -> JSONResponse:
        status_code = 400
        exc_name = exc.__class__.__name__
        if exc_name in ("ConnectionNotFoundError", "ProviderNotFoundError", "ProfileNotFoundError"):
            status_code = 404
        elif exc_name == "CredentialMissingError":
            status_code = 401

        return JSONResponse(
            status_code=status_code,
            content={
                "error": exc_name,
                "message": str(exc),
                "provider": exc.provider,
                "operation": exc.operation,
            },
        )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(connections_router)
    app.include_router(providers_router)
    app.include_router(proxy_router)
    return app
