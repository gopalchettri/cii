"""AI usage as the report routes take and show it (GET /v1/ai-usage...): counts only, each with the model,
activity and a one-line description; never a prompt or an answer."""

from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from app.core.constants import (
    AiApi,
    AiBucket,
    AiTask,
    AiUsageGroup,
    AiUsageLimits,
    AiUsageMessage,
    AiUsageOutcome,
    Module,
)

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

_PAGE_LIMIT = (
    f"Items per page, 1 to {AiUsageLimits.PAGE_SIZE_MAX}. Default {AiUsageLimits.PAGE_SIZE_DEFAULT}."
)
_PAGE_AFTER = "The `next` value of the page before, for the page after it. Leave empty for the first page."
_SESSION_ID = (
    "A session's id: a threat scenario run's id (POST /v1/sessions answered it), which its remediation "
    "plans' calls carry too, or a service mapping's id. Report 2 shows each API call's `session_id`."
)


class UsageCounts(BaseModel):
    """Every count of a set of usage rows."""

    total_ai_calls: int = Field(0, description="Attempts sent to a model (a reused answer is none).")
    successful_calls: int = Field(0, description="Attempts that ended `ok`.")
    failed_calls: int = Field(0, description="Attempts that did not end `ok`; `outcomes` says how.")
    asks: int = Field(0, description="Questions put to the AI; one ask may take several attempts.")
    extra_attempts: int = Field(
        0, description="Attempts beyond one per ask: retries, a fallback model, re-asks."
    )
    reused_answers: int = Field(0, description="Earlier answers used again, with no call made.")
    outcomes: dict[str, int] = Field(
        default_factory=dict,
        description=f"Rows per outcome ({', '.join(AiUsageOutcome)}); `reused` is an earlier answer used "
        "again, not an attempt. An outcome with none is left out.",
    )
    tokens_in: int = Field(
        0,
        description="Input tokens: chat prompts, and embedding and rerank inputs as the gateway counts "
        "them (recorded from 2026-10-30; a local reranker records none).",
    )
    tokens_out: int = Field(
        0, description="Answer tokens of chat calls; a rerank's output tokens when its gateway names any."
    )
    seconds: float = Field(0.0, description="Time the attempts took, added up.")


class PartCounts(BaseModel):
    """One part of a module's work (threats, scenario, controls, remediation, service_mapper)."""

    label: str = Field(description="The part's name, e.g. Finding threats.")
    description: str = Field(description="What the AI does in this part.")
    total_ai_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    by_task: dict[str, int] = Field(
        default_factory=dict,
        description="AI calls per task in this part, in reports 2 and 3. Always empty in totals (report 1): "
        "group by task there, and each row's `key` names it.",
    )


class ActivityUsage(BaseModel):
    """One activity (a task in a part) on one model."""

    bucket: str = Field(description="The part of the work, e.g. threats.")
    bucket_label: str
    task: str = Field(description="The AI task, e.g. relevance_gate.")
    activity: str = Field(description="The task's name in this part, e.g. Relevance check.")
    description: str = Field(description="What the AI does for this activity.")
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

    request_id: str = Field(description="The API call's X-Request-Id: open it with report 3.")
    session_id: str | None = None
    module: str | None = None
    api: str | None = None
    api_label: str = Field("", description="The API call's name, e.g. Create scenario.")
    api_description: str = Field("", description="What the API call starts.")
    entity_id: EntityId | None = Field(None, description="The X-Entity-Id of the caller.")
    client_id: str | None = Field(None, description="The client id of the caller's X-API-Key.")
    first_at: datetime = Field(description="When its first AI call was made.")
    last_at: datetime = Field(description="When its last AI call was made.")
    models: dict[str, int] = Field(default_factory=dict, description="AI calls per model.")
    buckets: dict[str, PartCounts] = Field(
        default_factory=dict,
        description="AI calls per part; every part of the module is listed, 0 when none.",
    )


class RequestUsageDetail(RequestUsage):
    activities: list[ActivityUsage] = Field(
        description=f"Each activity on each model, by part ({', '.join(AiBucket)}), then by task name: not "
        "the order the calls ran."
    )


class SessionUsage(UsageCounts):
    requests: int = Field(0, description="API calls of the session that made AI calls.")
    models: dict[str, int] = Field(default_factory=dict)
    buckets: dict[str, PartCounts] = Field(default_factory=dict)


class RequestUsageList(BaseModel):
    session_id: str | None = None
    summary: SessionUsage | None = Field(None, description="The whole session's counts, with `session_id`.")
    items: list[RequestUsage]
    next: str | None = Field(None, description="Pass as `after` for the next page; null on the last page.")


class TotalsRow(UsageCounts):
    """One group of a totals report: its key (the `group_by` fields) and its counts."""

    key: dict[str, EntityId] = Field(
        description="The group: a value per `group_by` field; empty text for no module or API (shared work)."
    )
    requests: int = Field(0, description="API calls whose first AI call falls in this group.")
    api_label: str | None = Field(None, description="With module and api in `group_by`.")
    api_description: str | None = None
    activity: str | None = Field(None, description="With bucket and task in `group_by`.")
    activity_description: str | None = None
    buckets: dict[str, PartCounts] = Field(default_factory=dict)


class UsageTotals(BaseModel):
    since: datetime = Field(description="The range's start, rounded down to the hour, in `tz`.")
    until: datetime = Field(description="The range's end (not included), rounded up to the hour, in `tz`.")
    tz: str
    group_by: list[AiUsageGroup]
    truncated: bool = Field(
        False,
        description=f"More than {AiUsageLimits.MAX_GROUPS:,} groups: only the first are listed (`total` "
        "still counts all). Narrow the range or the filters.",
    )
    total: UsageCounts = Field(description="The whole range's counts, every group together.")
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
    outcome: str = Field(description="ok, unreadable, truncated, unavailable, error, or reused.")
    reason: str | None = Field(None, description="Why it failed, when known, e.g. ai_down.")
    error_type: str | None = None
    ask_id: str | None = Field(None, description="The ask it belongs to: retries of one ask share it.")
    try_no: int | None = Field(None, description="Its try within the ask, from 1; null for a reused answer.")
    reask: bool | None = None
    request_id: str | None = None
    session_id: str | None = None
    record_id: str | None = Field(None, description="The run, plan or mapping it worked on.")
    epoch: int | None = None
    attempt: int | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    seconds: float | None = None


class UsageCallList(BaseModel):
    items: list[UsageCall]
    next: str | None = Field(None, description="Pass as `after` for the next page; null on the last page.")


class UsageFilters(BaseModel):
    """Narrow a report to these values (any left out: all)."""

    model_config = ConfigDict(extra="forbid")

    module: Module | None = Field(
        default=None,
        description="Only this module's AI calls. The three with API calls are threat_scenarios, remediation "
        "and service_mapper; the others run in the background. Empty: every module.",
    )
    api: AiApi | None = Field(
        default=None,
        description="Only this API call's AI calls. `regenerate` is in all three modules: pick the module "
        "too. Empty: every API call.",
    )
    # As X-Entity-Id: ASCII digits only (a pattern's \d takes other scripts' digits too, which int() may not)
    entity_id: str | None = Field(
        default=None,
        pattern=r"^[0-9]{1,18}$",
        description="Only this entity's calls: the X-Entity-Id the caller sent (digits), e.g. `125`.",
    )
    client_id: str | None = Field(
        default=None,
        max_length=64,
        description="Only this API client's calls: the client id of the X-API-Key that started the work "
        "(report 2 shows each API call's `client_id`).",
    )


class UsageTotalsQuery(UsageFilters):
    """A totals report: `since`/`until` (default: the last 30 days; at most 366), added up by `group_by` in
    `tz` (a whole number of hours from UTC, e.g. Asia/Dubai)."""

    since: ReportTime | None = Field(
        default=None,
        description="The range's start, ISO 8601 with a time zone, e.g. `2026-10-01T00:00:00+04:00` or "
        "`2026-10-01T00:00:00Z`; rounded down to the hour. Default: "
        f"{AiUsageLimits.DEFAULT_SPAN_DAYS} days before `until`; at most {AiUsageLimits.MAX_SPAN_DAYS} days.",
    )
    until: ReportTime | None = Field(
        default=None,
        description="The range's end (not included), e.g. `2026-11-01T00:00:00+04:00`; rounded up to the "
        "hour. Default: now.",
    )
    tz: str = Field(
        default="UTC",
        max_length=64,
        description="The time zone of the answer's times and of hour, day and month groups, e.g. "
        "`Asia/Dubai`: an IANA name a whole number of hours from UTC (Asia/Kolkata, +5:30, is refused: "
        "totals are kept per hour).",
    )
    group_by: list[AiUsageGroup] = Field(
        default=[AiUsageGroup.MODULE, AiUsageGroup.API],
        max_length=6,
        description="What to add up by; pick several to combine (e.g. day and module). hour, day and month "
        "are in `tz`; bucket is the part of the work; task the AI task. Default: module and api. At most 6.",
    )
    bucket: AiBucket | None = Field(
        default=None,
        description="Only this part of the work. `shared`: library and evidence indexing no request asked "
        "for. Empty: every part.",
    )
    task: list[AiTask] = Field(
        default_factory=list,
        max_length=20,
        description="Only these AI tasks; pick several for any of them. Empty: every task.",
    )
    model: str | None = Field(
        default=None,
        description="Only this model, exactly as the env file names it, e.g. `openai/Kimi-K2.6`. Empty: "
        "every model.",
    )


class RequestUsageQuery(UsageFilters):
    """The requests of one session, or of a range of at most 366 days (default: the last day)."""

    session_id: str | None = Field(
        default=None,
        max_length=64,
        description=f"{_SESSION_ID} Lists its API calls live, with the session's totals in `summary`; "
        "`since` and `until` are then not used.",
    )
    since: ReportTime | None = Field(
        default=None,
        description="Without `session_id`: API calls whose first AI call is at or after this time, ISO 8601 "
        "with a time zone, e.g. `2026-10-29T00:00:00+04:00`. Default: a day before `until`; at most "
        f"{AiUsageLimits.MAX_SPAN_DAYS} days.",
    )
    until: ReportTime | None = Field(
        default=None,
        description="Without `session_id`: the range's end (not included), e.g. `2026-10-30T00:00:00+04:00`. "
        "Default: now.",
    )
    limit: int = Field(
        default=AiUsageLimits.PAGE_SIZE_DEFAULT, ge=1, le=AiUsageLimits.PAGE_SIZE_MAX, description=_PAGE_LIMIT
    )
    after: str | None = Field(default=None, max_length=200, description=_PAGE_AFTER)


class UsageCallQuery(BaseModel):
    """Every AI attempt of one request or one session, newest first."""

    model_config = ConfigDict(extra="forbid")

    request_id: str | None = Field(
        default=None,
        max_length=64,
        description="One API call's attempts: its X-Request-Id, or a `request_id` from report 2. Give this "
        "or `session_id`.",
    )
    session_id: str | None = Field(
        default=None,
        max_length=64,
        description=f"{_SESSION_ID} Every attempt of the session. Give this or `request_id`.",
    )
    limit: int = Field(
        default=AiUsageLimits.PAGE_SIZE_DEFAULT, ge=1, le=AiUsageLimits.PAGE_SIZE_MAX, description=_PAGE_LIMIT
    )
    after: str | None = Field(default=None, max_length=200, description=_PAGE_AFTER)
