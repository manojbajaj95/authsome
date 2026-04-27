"""AuthsomeContext — thin wiring container for the authsome runtime.

Assembles Vault, AuthLayer, and ProxyRunner once per CLI invocation.
No business logic lives here — only dependency wiring.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
    home: Path

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
        from authsome.vault.storage import SQLiteStorage

        resolved_home = home or Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))
        cls._ensure_initialized(resolved_home)

        config_path = resolved_home / "config.json"
        providers_dir = resolved_home / "providers"
        profiles_dir = resolved_home / "profiles"
        master_key_path = resolved_home / "master.key"

        config = GlobalConfig()
        if config_path.exists():
            try:
                config = GlobalConfig.model_validate_json(config_path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to parse config.json, using defaults")

        crypto_mode = config.encryption.mode if config.encryption else "local_key"
        identity = profile or config.default_profile

        # Vault setup: resolver defines WHERE stores live, while Vault handles its own crypto
        def storage_resolver(profile_name: str) -> SQLiteStorage:
            profile_dir = profiles_dir / profile_name
            if not profile_dir.exists():
                from authsome.errors import ProfileNotFoundError

                raise ProfileNotFoundError(profile_name)
            return SQLiteStorage(profile_dir)

        vault = Vault(
            storage_resolver=storage_resolver,
            crypto_mode=crypto_mode,
            master_key_path=master_key_path,
        )

        registry = ProviderRegistry(providers_dir)
        auth = AuthLayer(vault=vault, registry=registry, identity=identity, profiles_dir=profiles_dir)
        proxy = ProxyRunner(auth=auth)

        return cls(vault=vault, auth=auth, proxy=proxy, home=resolved_home)

    def doctor(self) -> dict[str, Any]:
        """Run diagnostic checks on the current environment."""
        home = self.auth.registry.providers_dir.parent
        results: dict[str, Any] = {
            "home_exists": home.exists(),
            "version_file": (home / "version").exists(),
            "config_file": (home / "config.json").exists(),
            "providers_dir": self.auth.registry.providers_dir.exists(),
            "profiles_dir": (home / "profiles").exists(),
            "encryption": False,
            "store": False,
            "providers_count": 0,
            "profiles_count": 0,
            "issues": [],
        }

        try:
            self.vault.put("__doctor_test__", "ok", profile=self.auth.identity)
            val = self.vault.get("__doctor_test__", profile=self.auth.identity)
            self.vault.delete("__doctor_test__", profile=self.auth.identity)
            results["encryption"] = True
            results["store"] = val == "ok"
        except Exception as exc:
            results["issues"].append(f"Vault: {exc}")

        try:
            results["providers_count"] = len(self.auth.list_providers())
        except Exception as exc:
            results["issues"].append(f"Providers: {exc}")

        try:
            results["profiles_count"] = len(self.auth.list_profiles())
        except Exception as exc:
            results["issues"].append(f"Profiles: {exc}")

        return results

    @classmethod
    def _ensure_initialized(cls, home: Path) -> None:
        """Ensure the home directory and default profile are set up."""
        if (home / "version").exists() and (home / "profiles" / "default").exists():
            return

        home.mkdir(parents=True, exist_ok=True)
        (home / "providers").mkdir(parents=True, exist_ok=True)
        (home / "profiles" / "default").mkdir(parents=True, exist_ok=True)

        # Initialize version file
        version_file = home / "version"
        if not version_file.exists():
            version_file.write_text("2\n", encoding="utf-8")

        # Initialize default config
        config_file = home / "config.json"
        if not config_file.exists():
            from authsome.auth.models.config import GlobalConfig

            config = GlobalConfig()
            config_file.write_text(config.model_dump_json(indent=2), encoding="utf-8")

        # Initialize default profile metadata
        profile_dir = home / "profiles" / "default"
        metadata_path = profile_dir / "metadata.json"
        if not metadata_path.exists():
            from authsome.auth.models.profile import ProfileMetadata
            from authsome.utils import utc_now

            now = utc_now()
            metadata = ProfileMetadata(
                name="default",
                created_at=now,
                updated_at=now,
                description="Default local profile",
            )
            metadata_path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")

    def close(self) -> None:
        self.vault.close()

    def __enter__(self) -> AuthsomeContext:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
