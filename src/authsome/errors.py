"""Error hierarchy for authsome.

Spec §19.2: Expected error categories mapped to typed exceptions.
"""


class AuthsomeError(Exception):
    """Base exception for all authsome errors."""

    def __init__(self, message: str, *, provider: str | None = None, operation: str | None = None) -> None:
        self.provider = provider
        self.operation = operation
        parts: list[str] = []
        if provider:
            parts.append(f"[{provider}]")
        if operation:
            parts.append(f"({operation})")
        parts.append(message)
        super().__init__(" ".join(parts))


class ProviderNotFoundError(AuthsomeError):
    """Raised when a requested provider definition cannot be found."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Provider '{name}' not found", provider=name)


class UnsupportedAuthTypeError(AuthsomeError):
    """Raised when a provider's auth_type is not supported."""

    def __init__(self, auth_type: str, *, provider: str | None = None) -> None:
        super().__init__(f"Unsupported auth type: {auth_type}", provider=provider)


class UnsupportedFlowError(AuthsomeError):
    """Raised when a provider's flow type is not implemented."""

    def __init__(self, flow: str, *, provider: str | None = None) -> None:
        super().__init__(f"Unsupported flow: {flow}", provider=provider)


class CredentialMissingError(AuthsomeError):
    """Raised when expected credentials are not available."""

    def __init__(self, message: str = "Credential not found", *, provider: str | None = None) -> None:
        super().__init__(message, provider=provider)


class InputCancelledError(AuthsomeError):
    """Raised when a user cancels an interactive credential prompt."""

    def __init__(self, message: str = "Credential entry was cancelled") -> None:
        super().__init__(message, operation="input")


class TokenExpiredError(AuthsomeError):
    """Raised when an access token is expired and cannot be refreshed."""

    def __init__(self, *, provider: str | None = None) -> None:
        super().__init__("Access token expired", provider=provider)


class RefreshFailedError(AuthsomeError):
    """Raised when a token refresh attempt fails."""

    def __init__(self, reason: str = "Unknown error", *, provider: str | None = None) -> None:
        super().__init__(f"Token refresh failed: {reason}", provider=provider)


class EncryptionUnavailableError(AuthsomeError):
    """Raised when the encryption backend is unavailable."""

    def __init__(self, reason: str = "Encryption backend unavailable") -> None:
        super().__init__(reason)


class StoreUnavailableError(AuthsomeError):
    """Raised when the credential store cannot be accessed."""

    def __init__(self, reason: str = "Credential store unavailable") -> None:
        super().__init__(reason)


class InvalidProviderSchemaError(AuthsomeError):
    """Raised when a provider definition fails validation."""

    def __init__(self, message: str, *, provider: str | None = None) -> None:
        super().__init__(f"Invalid provider schema: {message}", provider=provider)


class ProfileNotFoundError(AuthsomeError):
    """Raised when a requested profile does not exist."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Profile '{name}' not found")


class ConnectionNotFoundError(AuthsomeError):
    """Raised when a requested connection does not exist."""

    def __init__(
        self,
        *,
        provider: str,
        connection: str = "default",
        profile: str = "default",
    ) -> None:
        super().__init__(
            f"Connection '{connection}' not found for provider '{provider}' in profile '{profile}'",
            provider=provider,
        )


class AuthenticationFailedError(AuthsomeError):
    """Raised when an authentication flow fails."""

    def __init__(self, reason: str, *, provider: str | None = None) -> None:
        super().__init__(f"Authentication failed: {reason}", provider=provider)


class DiscoveryError(AuthsomeError):
    """Raised when OAuth discovery (.well-known) fails."""

    def __init__(self, reason: str, *, provider: str | None = None) -> None:
        super().__init__(f"Discovery failed: {reason}", provider=provider)
