"""External intelligence as the admin API shows it: the switch, the health report with the evidence settings,
the start of a refresh, the import schedule and the control links."""

import re
from datetime import datetime
from typing import Any, Self
from zoneinfo import available_timezones

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.core.constants import IntelSchedule, IntelScheduleMessage, IntelSource, ScheduleFrequency


class IntelSwitchBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


class IntelRefreshBody(BaseModel):
    """`source`: refresh only this source now; none = every source."""

    model_config = ConfigDict(extra="forbid")

    source: IntelSource | None = None


class IntelSwitchOut(BaseModel):
    env_enabled: bool  # EXTERNAL_INTELLIGENCE_ENABLED, the master switch
    runtime_enabled: bool  # the admin's switch
    effective: bool  # on only when both are on
    changed_at: datetime | None = None
    changed_by: str | None = None
    refresh_job_id: str | None = None  # the refresh turning it on queued; none when one was already queued
    refresh_not_queued: str | None = None  # turned on, but its refresh could not be queued: why


class EvidenceSettingsOut(BaseModel):
    """The setting that decides what counts as evidence, so an uncalibrated environment is visible."""

    rerank_model: str  # the model's name only, never its folder or address
    threshold: float  # EVIDENCE_SIMILARITY_THRESHOLD, on that model's own 0-100 scale
    threshold_calibrated: bool  # true only at the threshold an operator calibrated for that model
    threshold_calibrated_on: str | None = None  # that calibration's date


class IntelHealthOut(BaseModel):
    switch: IntelSwitchOut
    snapshot_id: str | None = None
    sources: list[dict[str, Any]]
    pending_sources: list[str] = []  # sources still waiting for their first data
    no_data: bool = False  # no source has ever succeeded
    evidence: EvidenceSettingsOut


class IntelScheduleBody(BaseModel):
    """Body of PUT /v1/tsg/intel/schedule: when the import runs by itself. An unknown field is refused."""

    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool
    frequency: ScheduleFrequency
    day_of_week: int | None = Field(default=None, ge=0, le=6)  # Monday = 0; read only when weekly
    time: str = Field(pattern=IntelSchedule.TIME_PATTERN)  # HH:MM in `timezone`
    timezone: str  # an IANA name: UTC, Asia/Dubai

    @field_validator("timezone")
    @classmethod
    def check_timezone(cls, value: str) -> str:
        """Only a time zone this server knows."""
        if value not in available_timezones():
            raise ValueError(IntelScheduleMessage.TIMEZONE_UNKNOWN.format(timezone=value))
        return value

    @model_validator(mode="after")
    def check_day_of_week(self) -> Self:
        """A weekly schedule names its day; a daily one keeps none."""
        if self.frequency == ScheduleFrequency.DAILY:
            self.day_of_week = None
        elif self.day_of_week is None:
            raise ValueError(IntelScheduleMessage.DAY_REQUIRED)
        return self


class IntelScheduleOut(BaseModel):
    """The saved schedule, or the defaults while none is saved."""

    enabled: bool
    frequency: ScheduleFrequency
    day_of_week: int | None = None
    time: str
    timezone: str
    next_run_at: datetime | None = None  # none while disabled
    last_run_at: datetime | None = None  # the last import the schedule started
    updated_at: datetime | None = None  # none: never saved


class ControlLinksSummary(BaseModel):
    """How far the ATT&CK mitigations are linked to library controls."""

    mitigations: int  # mitigations the stored ATT&CK data lists that have a prepared record
    linked: int  # of them, with at least one library control
    without_links: int  # of them, with none
    not_prepared: int = 0  # listed mitigations with no record yet: never judged, or their judging failed
    prepared_at: datetime | None = None  # the newest preparation; none: nothing prepared yet


MARKER = re.compile(r"\[(\d+(?:\s*,\s*\d+)*)\]")


class EvidenceView(BaseModel):
    """One cited evidence entry as the API serves it."""

    n: int
    ref: str
    kind: str
    source: str
    title: str
    url: str
    facts: list[str] = Field(default_factory=list)
    applicability: str | None = None  # always none: no technique has one; kept so the response keeps its shape
    published: str | None = None  # always none, as applicability
    modified: str | None = None  # the source's last change to the record
    fetched_at: str | None = None
    searched_at: str | None = None
    role: str | None = None  # "context": every entry is context
    supports: str | None = None  # the claim it supports
    mitigations: list[str] = Field(default_factory=list)  # what reduces it; the control search reads it


def markers_of(text: str) -> list[int]:
    """Every marker number in `text`, in order of appearance ("[1, 2]" gives 1 and 2)."""
    return [int(n) for found in MARKER.findall(text) for n in re.split(r"\s*,\s*", found)]


def cited_evidence(content: dict[str, Any]) -> list[EvidenceView]:
    """The stored evidence the scenario's statement and risk cite, in marker order; none cited, none shown."""
    by_number = {item.get("n"): item for item in content.get("evidence") or []}
    text = f"{content.get('statement') or ''}\n{content.get('risk_statement') or ''}"
    cited = dict.fromkeys(n for n in markers_of(text) if n in by_number)
    return [EvidenceView.model_validate(by_number[n]) for n in cited]
