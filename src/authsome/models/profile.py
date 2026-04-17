"""Profile metadata models matching spec §8."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class ProfileMetadata(BaseModel):
    """
    Profile metadata stored in ~/.authsome/profiles/<name>/metadata.json.

    Spec §8: Required fields are name, created_at, updated_at.
    """

    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    description: str | None = None

    model_config = {"extra": "allow"}
