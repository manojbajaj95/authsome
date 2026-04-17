"""Abstract base class for credential stores."""

from __future__ import annotations

from abc import ABC, abstractmethod


class CredentialStore(ABC):
    """
    Abstract credential store interface.

    Spec §10: The credential store is logically a namespaced key-value store.
    Implementations must support get/set/delete/list_keys with string keys and values.
    """

    @abstractmethod
    def get(self, key: str) -> str | None:
        """
        Retrieve a value by key.

        Args:
            key: The namespaced key to look up.

        Returns:
            The stored JSON string value, or None if not found.
        """
        ...

    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """
        Store a value by key, creating or overwriting.

        Args:
            key: The namespaced key.
            value: The JSON string value to store.
        """
        ...

    @abstractmethod
    def delete(self, key: str) -> bool:
        """
        Delete a key from the store.

        Args:
            key: The namespaced key to delete.

        Returns:
            True if the key existed and was deleted, False otherwise.
        """
        ...

    @abstractmethod
    def list_keys(self, prefix: str = "") -> list[str]:
        """
        List all keys matching a prefix.

        Args:
            prefix: Key prefix to filter by. Empty string returns all keys.

        Returns:
            List of matching key strings.
        """
        ...

    @abstractmethod
    def close(self) -> None:
        """Close the store and release resources."""
        ...

    def __enter__(self) -> CredentialStore:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
