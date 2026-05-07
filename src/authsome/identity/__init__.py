"""Local identity helpers.

V1 intentionally supports a single local identity. Multi-profile/user/org
support should grow from this module later instead of leaking profile arguments
through server and CLI APIs.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_IDENTITY = "default"


@dataclass(frozen=True)
class Identity:
    """The current local identity."""

    name: str = DEFAULT_IDENTITY


def current() -> Identity:
    """Return the current local identity."""
    return Identity()
