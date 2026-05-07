"""Shared utility functions for authsome."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any


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
      profile:<profile_name>:<provider_name>:client
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
        elif record_type == "client":
            return f"profile:{profile}:{provider}:client"

    raise ValueError(
        f"Cannot build store key with profile={profile}, provider={provider}, "
        f"record_type={record_type}, connection={connection}"
    )


def redact(record: Any, redacted_value: str = "***REDACTED***") -> dict[str, Any]:
    """
    Return a dict of a Pydantic model with Sensitive-annotated fields replaced.

    Uses get_type_hints(include_extras=True) to detect Annotated[..., Sensitive()]
    fields and replaces their values with redacted_value before display.
    """
    import typing

    from authsome.auth.models.connection import Sensitive

    data = record.model_dump(mode="json")
    try:
        hints = typing.get_type_hints(type(record), include_extras=True)
    except Exception:
        return data

    for field_name, hint in hints.items():
        if typing.get_origin(hint) is typing.Annotated:
            metadata = typing.get_args(hint)[1:]
            if any(isinstance(m, Sensitive) for m in metadata):
                if data.get(field_name) is not None:
                    data[field_name] = redacted_value
    return data


def require_os_auth(action_name: str) -> bool:
    """
    Prompt the user for OS-level authentication (e.g., Touch ID on macOS)
    before allowing a sensitive action. Returns True if authenticated, False otherwise.
    """
    import subprocess
    import sys

    if sys.platform == "darwin":
        prompt = f"Authsome requires authentication to {action_name}."
        script = f'do shell script "echo authenticated" with prompt "{prompt}" with administrator privileges'
        try:
            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False
    elif sys.platform.startswith("linux"):
        import shutil

        if shutil.which("pkexec"):
            try:
                subprocess.run(["pkexec", "true"], check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError:
                return False
        elif shutil.which("sudo"):
            print(f"Authsome requires authentication to {action_name}.")
            try:
                subprocess.run(["sudo", "-v"], check=True)
                return True
            except subprocess.CalledProcessError:
                return False
        return False
    elif sys.platform == "win32":
        import ctypes
        import getpass
        import os
        from ctypes import wintypes

        try:
            password = getpass.getpass(f"Authsome requires authentication to {action_name}. Password: ")
            if not password:
                return False

            LOGON32_LOGON_INTERACTIVE = 2
            LOGON32_PROVIDER_DEFAULT = 0

            token = wintypes.HANDLE()
            username = os.environ.get("USERNAME", "")

            result = ctypes.windll.advapi32.LogonUserW(
                username,
                None,
                password,
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                ctypes.byref(token),
            )
            if result:
                ctypes.windll.kernel32.CloseHandle(token)
                return True
            return False
        except (KeyboardInterrupt, EOFError):
            return False

    return False
