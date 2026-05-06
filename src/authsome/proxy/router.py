"""Route match result type for proxy routing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteMatch:
    """Result of a successful route resolution."""

    provider: str
    connection: str | None = None
