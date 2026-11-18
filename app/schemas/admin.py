"""The bodies of the API-client endpoints."""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints


class MintRequest(BaseModel):
    # Stripped BEFORE the length check, so "   " is refused instead of stored as an empty name.
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)] = Field(
        examples=["shield-frontend"]
    )
    description: str | None = Field(default=None, max_length=500)


class ApiClientOut(BaseModel):
    client_id: str
    name: str
    description: str | None = None
    key_prefix: str
    active: bool
    created_at: datetime
    created_by: str | None = None
    revoked_at: datetime | None = None
    revoked_by: str | None = None


class MintedApiClient(ApiClientOut):
    api_key: str = Field(description="Shown only in this response. Store it now; it cannot be recovered.")


class ApiClientList(BaseModel):
    items: list[ApiClientOut]
    total: int
