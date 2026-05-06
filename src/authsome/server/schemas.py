"""Server request and response schemas.

These are HTTP boundary models. They intentionally avoid exposing internal
auth/vault models directly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    mode: Literal["local"] = "local"
    pid: int


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    checks: dict[str, str] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)


class OpenUrlAction(BaseModel):
    type: Literal["open_url"]
    url: str


class DeviceCodeAction(BaseModel):
    type: Literal["device_code"]
    verification_uri: str
    verification_uri_complete: str | None = None
    user_code: str
    interval: int = 5


class NoneAction(BaseModel):
    type: Literal["none"] = "none"


NextAction = Annotated[OpenUrlAction | DeviceCodeAction | NoneAction, Field(discriminator="type")]


class AuthSessionResponse(BaseModel):
    id: str
    provider: str
    connection: str
    status: str
    message: str | None = None
    error: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    next_action: NextAction = Field(default_factory=NoneAction)


class StartAuthSessionRequest(BaseModel):
    provider: str
    connection: str = "default"
    flow: str | None = None
    scopes: list[str] | None = None
    base_url: str | None = None
    force: bool = False


class ResumeAuthSessionRequest(BaseModel):
    data: dict[str, Any] = Field(default_factory=dict)


class CredentialResolutionRequest(BaseModel):
    provider: str
    connection: str | None = None


class CredentialResolutionResponse(BaseModel):
    provider: str
    connection: str
    headers: dict[str, str]
    expires_at: datetime | None = None


class ProviderRoute(BaseModel):
    provider: str
    connection: str | None = None
    host_url: str
    auth_endpoint_paths: list[str] = Field(default_factory=list)


class ProxyRoutesResponse(BaseModel):
    routes: list[ProviderRoute]
