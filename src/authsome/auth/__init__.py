"""Auth domain package."""

from authsome.auth.service import AuthService

# Backward-compatible alias while downstream code migrates.
AuthLayer = AuthService

__all__ = ["AuthLayer", "AuthService"]
