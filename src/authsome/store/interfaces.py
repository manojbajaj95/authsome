"""Unified storage interfaces for Authsome.

This module defines the abstract boundaries for all persistence in Authsome.
A single `AppStore` interface groups config, profiles, providers, and
vault KV storage, allowing the entire storage backend to be swapped out
for remote environments.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authsome.auth.models.config import GlobalConfig
    from authsome.auth.models.profile import ProfileMetadata
    from authsome.auth.models.provider import ProviderDefinition


class VaultStorage(ABC):
    """Abstract key-value storage backend for a single profile's vault."""

    @abstractmethod
    def get(self, key: str) -> str | None:
        """Retrieve a value by key. Returns None if not found."""
        ...

    @abstractmethod
    def put(self, key: str, value: str) -> None:
        """Store a value by key (upsert)."""
        ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key. Returns True if the key existed."""
        ...

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        """List all keys matching a prefix."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Release any resources held by the backend."""
        ...


class AppStore(ABC):
    """Unified storage interface for all Authsome persistence."""

    @property
    @abstractmethod
    def home(self) -> Path:
        """Get the base directory for this storage system."""
        ...

    # ── Initialization ────────────────────────────────────────────────────

    @abstractmethod
    def ensure_initialized(self) -> None:
        """Ensure the storage system is initialized (e.g. default profile exists)."""
        ...

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the store is accessible and healthy."""
        ...

    # ── Config ────────────────────────────────────────────────────────────

    @abstractmethod
    def get_config(self) -> GlobalConfig:
        """Get global configuration."""
        ...

    @abstractmethod
    def save_config(self, config: GlobalConfig) -> None:
        """Save global configuration."""
        ...

    # ── Profiles ──────────────────────────────────────────────────────────

    @abstractmethod
    def get_profile(self, name: str) -> ProfileMetadata:
        """Get profile metadata. Raises ProfileNotFoundError if missing."""
        ...

    @abstractmethod
    def save_profile(self, metadata: ProfileMetadata) -> None:
        """Save profile metadata."""
        ...

    @abstractmethod
    def list_profiles(self) -> list[ProfileMetadata]:
        """List all profiles."""
        ...

    @abstractmethod
    def delete_profile(self, name: str) -> None:
        """Delete a profile and its vault."""
        ...

    # ── Providers ─────────────────────────────────────────────────────────

    @abstractmethod
    def get_provider(self, name: str) -> ProviderDefinition:
        """Get a custom provider definition. Raises ProviderNotFoundError if missing."""
        ...

    @abstractmethod
    def save_provider(self, definition: ProviderDefinition) -> None:
        """Save a custom provider definition."""
        ...

    @abstractmethod
    def list_providers(self) -> list[ProviderDefinition]:
        """List all custom providers."""
        ...

    @abstractmethod
    def delete_provider(self, name: str) -> None:
        """Delete a custom provider definition."""
        ...

    # ── Vault ─────────────────────────────────────────────────────────────

    @abstractmethod
    def get_vault_storage(self, profile: str) -> VaultStorage:
        """Get the KV storage backend for a specific profile's vault."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Close all underlying storage connections."""
        ...
