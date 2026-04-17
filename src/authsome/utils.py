"""Shared utility functions for authsome."""

from __future__ import annotations

import re
from datetime import UTC, datetime


def utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(UTC)


def to_rfc3339(dt: datetime) -> str:
    """Format a datetime as RFC 3339 / ISO 8601 in UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat().replace("+00:00", "Z")


def parse_rfc3339(s: str) -> datetime:
    """Parse an RFC 3339 datetime string."""
    s = s.replace("Z", "+00:00")
    return datetime.fromisoformat(s)


def is_filesystem_safe(name: str) -> bool:
    """
    Check if a name is safe for use as a filesystem path component.

    Spec §21.1: name must be filesystem-safe.
    """
    if not name:
        return False
    # Allow only alphanumeric, hyphens, underscores, dots (no leading dot)
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", name):
        return False
    # Block path traversal
    if ".." in name or "/" in name or "\\" in name:
        return False
    return True


def build_store_key(
    *,
    profile: str | None = None,
    provider: str | None = None,
    record_type: str | None = None,
    connection: str | None = None,
) -> str:
    """
    Build a namespaced key for the credential store.

    Spec §10.1 key namespace:
      provider:<provider_name>:definition
      profile:<profile_name>:<provider_name>:metadata
      profile:<profile_name>:<provider_name>:state
      profile:<profile_name>:<provider_name>:connection:<connection_name>
    """
    if record_type == "definition" and provider:
        return f"provider:{provider}:definition"

    if profile and provider:
        if record_type == "metadata":
            return f"profile:{profile}:{provider}:metadata"
        elif record_type == "state":
            return f"profile:{profile}:{provider}:state"
        elif record_type == "connection" and connection:
            return f"profile:{profile}:{provider}:connection:{connection}"

    raise ValueError(
        f"Cannot build store key with profile={profile}, provider={provider}, "
        f"record_type={record_type}, connection={connection}"
    )
