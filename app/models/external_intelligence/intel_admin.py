"""External intelligence as the admin API shows it: the switch, the health report with the evidence settings,
and the start of a refresh."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, StrictBool

from app.core.constants import IntelSource


class IntelSwitchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


class IntelRefreshBody(BaseModel):
    """`source`: refresh only this approved source now; none = every source that is due."""

    model_config = ConfigDict(extra="forbid")

    source: IntelSource | None = None


class IntelSourceRevoked(BaseModel):
    source: IntelSource
    records_purged: int


class IntelSourceApproved(BaseModel):
    source: IntelSource
    refresh_job_id: str | None = None  # the queued refresh of that source; none when one was already queued


class IntelSwitchOut(BaseModel):
    env_enabled: bool  # EXTERNAL_INTELLIGENCE_ENABLED, the master switch
    runtime_enabled: bool  # the admin's switch
    effective: bool  # on only when both are on
    changed_at: datetime | None = None
    changed_by: str | None = None


class EvidenceSettingsOut(BaseModel):
    """The setting that decides what counts as evidence, so an uncalibrated environment is visible."""

    rerank_model: str  # the model's name only, never its folder or address
    threshold: float  # EVIDENCE_SIMILARITY_THRESHOLD, on that model's own 0-100 scale
    threshold_calibrated: bool  # true only for a model an operator recorded a calibration of
    threshold_calibrated_on: str | None = None  # that calibration's date


class IntelHealthOut(BaseModel):
    switch: IntelSwitchOut
    snapshot_id: str | None = None
    sources: list[dict[str, Any]]
    stale: bool  # an approved source that has data is older than the age limit
    pending_sources: list[str] = []  # approved sources still waiting for their first data (not stale)
    no_data: bool = False  # no approved source has ever succeeded
    evidence: EvidenceSettingsOut
