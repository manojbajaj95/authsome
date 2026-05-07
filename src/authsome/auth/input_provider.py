"""InputProvider protocol and adapters for collecting credentials from users."""

from __future__ import annotations

from pydantic import BaseModel


class InputField(BaseModel):
    """A single field to collect from the user."""

    name: str
    label: str
    secret: bool = True
    default: str | None = None
    #: Optional regex (``re.fullmatch``) that the submitted value must satisfy.
    pattern: str | None = None
    #: Optional human-readable message shown when the value does not match ``pattern``.
    pattern_hint: str | None = None
