"""Global configuration models matching spec §7."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EncryptionConfig(BaseModel):
    """
    Encryption configuration block.

    Supported modes:
    - "local_key": Master key stored as a local file (~/.authsome/master.key).
                   Best for headless environments, CI, or systems without an OS keyring.
    - "keyring":   Master key stored in the OS keyring (macOS Keychain, GNOME Keyring, etc.).
                   Best for desktop environments with credential manager support.
    """

    mode: str = "local_key"


class GlobalConfig(BaseModel):
    """
    Global configuration stored in ~/.authsome/config.json.

    Spec §7: Required fields are spec_version and default_profile.
    Unknown fields are preserved per spec §6 rule 4.
    """

    spec_version: int = 1
    default_profile: str = "default"
    encryption: EncryptionConfig | None = Field(default_factory=EncryptionConfig)

    # Forward-compatible: preserve unknown fields
    extra_fields: dict[str, Any] = Field(default_factory=dict, exclude=True)

    model_config = {"extra": "allow"}
