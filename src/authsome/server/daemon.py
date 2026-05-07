"""Local daemon foreground runner."""

from __future__ import annotations

import uvicorn

from authsome.server.app import create_app

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7998


def serve(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Run the daemon in the foreground."""
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
