"""FastAPI dependency helpers."""

from __future__ import annotations

from fastapi import Request

from authsome.auth import AuthService
from authsome.auth.sessions import AuthSessionStore


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_auth_sessions(request: Request) -> AuthSessionStore:
    return request.app.state.auth_sessions
