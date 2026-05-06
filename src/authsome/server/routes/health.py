"""Health and readiness routes."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends

from authsome import __version__
from authsome.auth import AuthService
from authsome.server.routes._deps import get_auth_service
from authsome.server.schemas import HealthResponse, ReadyResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__, pid=os.getpid())


@router.get("/ready", response_model=ReadyResponse)
def ready(auth: AuthService = Depends(get_auth_service)) -> ReadyResponse:
    checks: dict[str, str] = {}
    issues: list[str] = []

    try:
        config = auth.app_store.get_config()
        checks["config"] = "ok" if config else "ok"
    except Exception as exc:
        checks["config"] = "failed"
        issues.append(f"config: {exc}")

    try:
        auth.list_providers()
        checks["providers"] = "ok"
    except Exception as exc:
        checks["providers"] = "failed"
        issues.append(f"providers: {exc}")

    try:
        auth.vault.put("__ready_test__", "ok", profile=auth.identity)
        value = auth.vault.get("__ready_test__", profile=auth.identity)
        auth.vault.delete("__ready_test__", profile=auth.identity)
        checks["vault"] = "ok" if value == "ok" else "failed"
        if value != "ok":
            issues.append("vault: readiness roundtrip failed")
    except Exception as exc:
        checks["vault"] = "failed"
        issues.append(f"vault: {exc}")

    return ReadyResponse(status="ready" if not issues else "not_ready", checks=checks, issues=issues)


@router.get("/whoami")
def whoami(auth: AuthService = Depends(get_auth_service)) -> dict[str, str]:
    config = auth.app_store.get_config()
    enc_mode = config.encryption.mode if config.encryption else "local_key"
    if enc_mode == "local_key":
        enc_desc = f"Local Key ({auth.app_store.home / 'master.key'})"
    elif enc_mode == "keyring":
        enc_desc = "OS Keyring"
    else:
        enc_desc = enc_mode
    return {
        "version": __version__,
        "home": str(auth.app_store.home),
        "active_identity": auth.identity,
        "encryption_backend": enc_desc,
    }
