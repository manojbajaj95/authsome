"""AuthsomeContext — thin wiring container for the authsome runtime.

Assembles Vault, AuthLayer, and ProxyRunner once per CLI invocation.
No business logic lives here — only dependency wiring.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from authsome.auth import AuthLayer
    from authsome.proxy.runner import ProxyRunner
    from authsome.vault import Vault


@dataclass
class AuthsomeContext:
    """Assembled runtime: vault + auth layer + proxy runner."""

    vault: Vault
    auth: AuthLayer
    proxy: ProxyRunner

    @classmethod
    def create(
        cls,
        home: Path | None = None,
        profile: str | None = None,
    ) -> AuthsomeContext:
        """Wire up all layers and return a ready-to-use context."""
        from authsome.auth import AuthLayer
        from authsome.auth.models.config import GlobalConfig
        from authsome.auth.providers.registry import ProviderRegistry
        from authsome.proxy.runner import ProxyRunner
        from authsome.vault import Vault

        resolved_home = home or Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))

        config_path = resolved_home / "config.json"
        config = GlobalConfig()
        if config_path.exists():
            try:
                config = GlobalConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to parse config.json, using defaults")

        crypto_mode = config.encryption.mode if config.encryption else "local_key"
        identity = profile or config.default_profile

        vault = Vault(resolved_home, crypto_mode=crypto_mode)
        registry = ProviderRegistry(resolved_home)
        auth = AuthLayer(vault=vault, registry=registry, identity=identity)
        proxy = ProxyRunner(auth=auth)

        return cls(vault=vault, auth=auth, proxy=proxy)

    def close(self) -> None:
        self.vault.close()

    def __enter__(self) -> AuthsomeContext:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
