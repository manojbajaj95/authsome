"""Concrete local dependency wiring for the daemon server."""

from __future__ import annotations

import os
from pathlib import Path

from authsome.auth import AuthService
from authsome.auth.providers.registry import ProviderRegistry
from authsome.identity import current
from authsome.store.local import LocalAppStore
from authsome.vault import Vault


def get_authsome_home() -> Path:
    """Return the local Authsome home directory."""
    return Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))


def create_auth_service(home: Path | None = None) -> AuthService:
    """Create the singleton auth service for the local daemon."""
    resolved_home = home or get_authsome_home()
    app_store = LocalAppStore(resolved_home)
    app_store.ensure_initialized()

    config = app_store.get_config()
    crypto_mode = config.encryption.mode if config.encryption else "local_key"
    vault = Vault(
        app_store=app_store,
        crypto_mode=crypto_mode,
        master_key_path=resolved_home / "master.key",
    )
    registry = ProviderRegistry(app_store)
    identity = current()
    return AuthService(vault=vault, registry=registry, app_store=app_store, identity=identity.name)
