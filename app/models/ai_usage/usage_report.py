"""AI usage as the report routes take and show it (GET /v1/ai-usage...): counts only, each with the model,
activity and a one-line description; never a prompt or an answer."""

from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.core.constants import AiUsageGroup, AiUsageLimits, AiUsageMessage

#: An entity id: a number as SQL Server keeps it (an older row may hold it as text).
EntityId = int | str


def reportable_time(moment: datetime) -> datetime:
    """A time a report reads by (its `since`, `until` or a page cursor's): within REPORT_YEARS, so no range
    arithmetic and no MongoDB date can overflow."""
    first, last = AiUsageLimits.REPORT_YEARS
    if not first <= moment.year <= last:
        raise ValueError(AiUsageMessage.YEAR_OUT_OF_RANGE.format(first=first, last=last))
    return moment


#: A time a report starts or ends at.
ReportTime = Annotated[datetime, AfterValidator(reportable_time)]


class UsageCounts(BaseModel):
    """Every count of a set of usage rows. `total_ai_calls`: attempts sent to a model (a reused answer is
    none); `failed_calls`: those that did not end ok; `asks`: questions put to the AI; `extra_attempts`:
    attempts beyond one per ask (retries, a fallback model, re-asks)."""

    total_ai_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    asks: int = 0
    extra_attempts: int = 0
    reused_answers: int = 0
    outcomes: dict[str, int] = Field(default_factory=dict)
    tokens_in: int = 0
    tokens_out: int = 0
    seconds: float = 0.0


class PartCounts(BaseModel):
    """One part of a module's work (threats, scenario, controls, remediation, service_mapper)."""

    label: str
    description: str
    total_ai_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    by_task: dict[str, int] = Field(default_factory=dict)


class ActivityUsage(BaseModel):
    """One activity (a task in a part) on one model."""

    bucket: str
    bucket_label: str
    task: str
    activity: str
    description: str
    model: str
    total_ai_calls: int
    successful_calls: int
    failed_calls: int
    reused_answers: int
    tokens_in: int
    tokens_out: int
    seconds: float


class RequestUsage(UsageCounts):
    """One API call's AI work: who asked, when, on which models, in which parts."""

    request_id: str
    session_id: str | None = None
    module: str | None = None
    api: str | None = None
    api_label: str = ""
    api_description: str = ""
    entity_id: EntityId | None = None
    client_id: str | None = None
    first_at: datetime
    last_at: datetime
    models: dict[str, int] = Field(default_factory=dict)
    buckets: dict[str, PartCounts] = Field(default_factory=dict)


class RequestUsageDetail(RequestUsage):
    activities: list[ActivityUsage]


class SessionUsage(UsageCounts):
    requests: int = 0
    models: dict[str, int] = Field(default_factory=dict)
    buckets: dict[str, PartCounts] = Field(default_factory=dict)


class RequestUsageList(BaseModel):
    session_id: str | None = None
    summary: SessionUsage | None = None  # the whole session's, with `session_id`
    items: list[RequestUsage]
    next: str | None = None  # pass as `after` for the next page; none on the last


class TotalsRow(UsageCounts):
    """One group of a totals report: its key (the `group_by` fields) and its counts."""

    key: dict[str, EntityId]
    requests: int = 0  # API calls whose first AI call falls in this group
    api_label: str | None = None  # with module and api in `group_by`
    api_description: str | None = None
    activity: str | None = None  # with bucket and task in `group_by`
    activity_description: str | None = None
    buckets: dict[str, PartCounts] = Field(default_factory=dict)


class UsageTotals(BaseModel):
    since: datetime
    until: datetime
    tz: str
    group_by: list[AiUsageGroup]
    truncated: bool = False  # more groups than AiUsageLimits.MAX_GROUPS: narrow the range or the filters
    total: UsageCounts
    items: list[TotalsRow]


class UsageCall(BaseModel):
    """One AI attempt (or a reused answer), with what it was for and how it went."""

    id: str
    created_at: datetime
    module: str | None = None
    api: str | None = None
    bucket: str
    task: str
    activity: str
    description: str
    model: str | None = None
    outcome: str
    reason: str | None = None
    error_type: str | None = None
    ask_id: str | None = None
    try_no: int | None = None  # none for a reused answer: no attempt was made
    reask: bool | None = None
    request_id: str | None = None
    session_id: str | None = None
    record_id: str | None = None
    epoch: int | None = None
    attempt: int | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    seconds: float | None = None


class UsageCallList(BaseModel):
    items: list[UsageCall]
    next: str | None = None


class UsageFilters(BaseModel):
    """Narrow a report to these values (any left out: all)."""

    model_config = ConfigDict(extra="forbid")

    module: str | None = Field(default=None, max_length=64)
    api: str | None = Field(default=None, max_length=64)
    # As X-Entity-Id: ASCII digits only (a pattern's \d takes other scripts' digits too, which int() may not)
    entity_id: str | None = Field(default=None, pattern=r"^[0-9]{1,18}$")
    client_id: str | None = Field(default=None, max_length=64)


class UsageTotalsQuery(UsageFilters):
    """A totals report: `since`/`until` (default: the last 30 days; at most 366), added up by `group_by` in
    `tz` (a whole number of hours from UTC, e.g. Asia/Dubai)."""

    since: ReportTime | None = None
    until: ReportTime | None = None
    tz: str = Field(default="UTC", max_length=64)
    group_by: list[AiUsageGroup] = Field(default=[AiUsageGroup.MODULE, AiUsageGroup.API], max_length=6)
    bucket: str | None = None
    task: list[str] = Field(default_factory=list, max_length=20)
    model: str | None = None


class RequestUsageQuery(UsageFilters):
    """The requests of one session, or of a range of at most 366 days (default: the last day)."""

    session_id: str | None = Field(default=None, max_length=64)
    since: ReportTime | None = None
    until: ReportTime | None = None
    limit: int = Field(default=AiUsageLimits.PAGE_SIZE_DEFAULT, ge=1, le=AiUsageLimits.PAGE_SIZE_MAX)
    after: str | None = Field(default=None, max_length=200)


class UsageCallQuery(BaseModel):
    """Every AI attempt of one request or one session, newest first."""

    model_config = ConfigDict(extra="forbid")

    request_id: str | None = Field(default=None, max_length=64)
    session_id: str | None = Field(default=None, max_length=64)
    limit: int = Field(default=AiUsageLimits.PAGE_SIZE_DEFAULT, ge=1, le=AiUsageLimits.PAGE_SIZE_MAX)
    after: str | None = Field(default=None, max_length=200)
