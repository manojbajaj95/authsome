"""Runtime session models, API payload models, and client credential mode.

These models are shared across the runtime service, server, client, and
operator console.  They form the stable contract for session state and
credential resolution payloads.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from authsome.utils import utc_now


class SessionState(StrEnum):
    """Lifecycle states for an interactive auth session."""

    PENDING = "pending"
    WAITING_FOR_USER = "waiting_for_user"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class RuntimeSession(BaseModel):
    """Represents an interactive or stateful auth operation.

    Shared across PKCE, device code, and API key flows so the CLI,
    operator console, and future hosted clients all see the same
    lifecycle semantics.
    """

    session_id: str
    provider: str
    profile: str
    connection_name: str
    flow_type: str
    state: str = SessionState.PENDING
    status_message: str | None = None
    error_message: str | None = None
    payload: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class CredentialResolutionResponse(BaseModel):
    """Response from the credential resolution API."""

    provider: str
    connection_name: str
    profile: str
    headers: dict[str, str] = Field(default_factory=dict)
