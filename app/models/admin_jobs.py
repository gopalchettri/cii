"""Admin jobs as the API shows them (#18 start an embeddings build, #19 read it)."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.constants import AdminJobKind, Status


class AdminJobStarted(BaseModel):
    job_id: str
    status: Status


class EmbeddingsBuildResult(BaseModel):
    counts: dict[str, int] = Field(description="Rows each library holds now, each with its vector.")
    newly_embedded: dict[str, int] = Field(description="Vectors made while the build ran, per library.")


class AdminJobOut(BaseModel):
    job_id: str
    kind: AdminJobKind
    status: Status
    requested_by: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: EmbeddingsBuildResult | None = None
    error: dict[str, str] | None = None
