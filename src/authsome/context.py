"""AuthsomeContext — thin wiring container for the authsome runtime.

Assembles Vault, AuthLayer, and ProxyRunner once per CLI invocation.
No business logic lives here — only dependency wiring.

Two factory methods are provided:
- ``create()`` / ``create_local()`` — full local stack with in-process runtime
- ``create_remote()`` — thin client mode pointing at a hosted Auth runtime
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from authsome.auth import AuthLayer
    from authsome.proxy.runner import ProxyRunner
    from authsome.runtime.client import RuntimeClient
    from authsome.runtime.server import RuntimeServer
    from authsome.runtime.service import AuthRuntimeService
    from authsome.vault import Vault


@dataclass
class AuthsomeContext:
    """Assembled runtime: vault + auth layer + proxy runner + runtime.

    In **local mode** all fields are populated (vault, auth, proxy, runtime
    service/server/client).

    In **remote mode** only ``home``, ``runtime_client``, and ``proxy`` are
    meaningful.  The vault and auth layer live on the remote server.
    """

    vault: Vault | None
    auth: AuthLayer | None
    proxy: ProxyRunner | None
    home: Path
    runtime_service: AuthRuntimeService | None
    runtime_server: RuntimeServer | None
    runtime_client: RuntimeClient

    def require_local_auth(self) -> AuthLayer:
        """Return the AuthLayer, raising if running in remote mode."""
        if self.auth is None:
            raise RuntimeError("AuthLayer is not available in remote mode")
        return self.auth

    def require_local_proxy(self) -> ProxyRunner:
        """Return the ProxyRunner, raising if running in remote mode."""
        if self.proxy is None:
            raise RuntimeError("ProxyRunner is not available in remote mode")
        return self.proxy

    # ── Factory methods ───────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        home: Path | None = None,
        profile: str | None = None,
    ) -> AuthsomeContext:
        """Wire up all layers and return a ready-to-use context.

        This is the default entry point.
        """
        import sys

        if len(sys.argv) > 1 and sys.argv[1] == "daemon":
            return cls.create_local(home=home, profile=profile)
        return cls.create_remote(remote_url="http://127.0.0.1:7998", home=home)

    @classmethod
    def create_local(
        cls,
        home: Path | None = None,
        profile: str | None = None,
    ) -> AuthsomeContext:
        """Create a full local context with vault, auth, proxy, and in-process runtime."""
        from authsome.auth import AuthLayer
        from authsome.auth.providers.registry import ProviderRegistry
        from authsome.proxy.runner import ProxyRunner
        from authsome.runtime.client import InProcessRuntimeClient
        from authsome.runtime.server import RuntimeServer
        from authsome.runtime.service import AuthRuntimeService
        from authsome.store.local import LocalAppStore
        from authsome.vault import Vault

        resolved_home = home or Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))
        app_store = LocalAppStore(resolved_home)
        app_store.ensure_initialized()

        config = app_store.get_config()
        crypto_mode = config.encryption.mode if config.encryption else "local_key"
        identity = profile or config.default_profile
        master_key_path = resolved_home / "master.key"

        vault = Vault(
            app_store=app_store,
            crypto_mode=crypto_mode,
            master_key_path=master_key_path,
        )

        registry = ProviderRegistry(app_store)
        auth = AuthLayer(vault=vault, registry=registry, identity=identity, app_store=app_store)

        # Build runtime stack
        runtime_service = AuthRuntimeService(auth=auth)
        runtime_server = RuntimeServer(service=runtime_service)
        runtime_client = InProcessRuntimeClient(server=runtime_server)

        proxy = ProxyRunner(client=runtime_client)

        return cls(
            vault=vault,
            auth=auth,
            proxy=proxy,
            home=resolved_home,
            runtime_service=runtime_service,
            runtime_server=runtime_server,
            runtime_client=runtime_client,
        )

    @classmethod
    def create_remote(
        cls,
        remote_url: str,
        auth_token: str | None = None,
        home: Path | None = None,
    ) -> AuthsomeContext:
        """Create a thin remote context that delegates to a hosted Auth runtime.

        In this mode the CLI and proxy talk to a remote server over HTTPS.
        No local vault, auth layer, or runtime server are created.
        """
        from authsome.proxy.runner import ProxyRunner
        from authsome.runtime.client import HttpRuntimeClient

        resolved_home = home or Path(os.environ.get("AUTHSOME_HOME", str(Path.home() / ".authsome")))

        runtime_client = HttpRuntimeClient(base_url=remote_url, auth_token=auth_token)
        proxy = ProxyRunner(client=runtime_client)

        return cls(
            vault=None,
            auth=None,
            proxy=proxy,
            home=resolved_home,
            runtime_service=None,
            runtime_server=None,
            runtime_client=runtime_client,
        )

    # ── Diagnostics ───────────────────────────────────────────────────────

    def doctor(self) -> dict[str, Any]:
        """Run diagnostic checks on the current environment."""
        home = self.home
        results: dict[str, Any] = {
            "home_exists": home.exists(),
            "version_file": (home / "version").exists(),
            "config_file": (home / "config.json").exists(),
            "providers_dir": (home / "providers").exists(),
            "profiles_dir": (home / "profiles").exists(),
            "encryption": False,
            "store": False,
            "providers_count": 0,
            "profiles_count": 0,
            "issues": [],
        }

        if self.vault is None or self.auth is None:
            try:
                return self.runtime_client.doctor()
            except Exception as exc:
                results["issues"].append(f"Remote diagnostics failed: {exc}")
                return results

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

    # ── Lifecycle ─────────────────────────────────────────────────────────

    def close(self) -> None:
        if self.vault is not None:
            self.vault.close()

    def __enter__(self) -> AuthsomeContext:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
