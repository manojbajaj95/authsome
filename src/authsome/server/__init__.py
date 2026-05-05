"""HTTP server package for the local Authsome daemon."""

from authsome.server.app import create_app

__all__ = ["create_app"]
