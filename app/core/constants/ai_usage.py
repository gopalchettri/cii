"""AI usage tracking: the collections that keep it (never deleted), the APIs that start AI work, the part of
a module's work each AI call is counted in, the hourly totals and the report limits."""

from enum import StrEnum
from typing import Final

from app.core.constants.common import AiOutcome, AiTask, Module
from app.core.constants.jobs import TaskName


class AiUsageCollection(StrEnum):
    """Never deleted: no expiry, and their repositories refuse a delete."""

    USAGE = "tsg_ai_usage"  # one row per AI attempt sent to a model, and per earlier answer reused
    HOURLY = "tsg_ai_usage_hourly"  # the rows added up per UTC hour, for dashboards
    REQUESTS = "tsg_ai_usage_requests"  # one summary per API request, for request lists over a range


#: Where the previous release kept the AI call texts (expired after 14 days): copied in by the ai_usage_tools
#: copy-texts command (the rollback path in deploy/DEPLOYMENT_GUIDE.md).
PREVIOUS_AI_CALL_TEXTS: Final = "tsg_ai_calls"


class AiApi(StrEnum):
    """The API call that started a job's AI work (job.origin.api), stored on every usage row."""

    CREATE_SCENARIO = "create_scenario"  # POST /v1/sessions
    CREATE_SESSION = "create_session"  # POST /v1/create_session
    NEXT_SET = "next_set"  # POST /v1/sessions/{id}/scenarios/next-set
    REGENERATE = "regenerate"  # a module's regenerate call (scenarios, a plan, a mapping)
    CREATE_PLAN = "create_plan"  # POST /v1/remediation
    CREATE_MAPPING = "create_mapping"  # POST /v1/service-mapper
    MITRE_CREATE_SESSION = "mitre_create_session"  # POST /v1/mitre_create_session
    MITRE_NEXT_SET = "mitre_next_set"  # POST /v1/mitre_sessions/{id}/next-set


class AiBucket(StrEnum):
    """The part of a module's work an AI call is counted in."""

    THREATS = "threats"
    SCENARIO = "scenario"
    CONTROLS = "controls"
    REMEDIATION = "remediation"
    SERVICE_MAPPER = "service_mapper"
    SHARED = "shared"  # work every job shares (library and evidence indexes): no request of its own


class AiUsageOutcome(StrEnum):
    """A usage row's outcome: an AI call's (AiOutcome), or an earlier answer reused with no call."""

    OK = AiOutcome.OK
    UNREADABLE = AiOutcome.UNREADABLE
    TRUNCATED = AiOutcome.TRUNCATED
    UNAVAILABLE = AiOutcome.UNAVAILABLE
    ERROR = AiOutcome.ERROR
    REUSED = "reused"


class AiUsageReason(StrEnum):
    """Why a call that answered is still a failure, beside AiOutage's outage reasons."""

    NO_CHOICES = "no_choices"  # the model answered with no choice at all


#: A chat call's part, by its task.
CHAT_TASK_BUCKETS: Final[dict[str, AiBucket]] = {
    AiTask.RELEVANCE_GATE: AiBucket.THREATS,
    AiTask.GAP_FILL: AiBucket.THREATS,
    AiTask.THREAT_ACTIONS: AiBucket.SCENARIO,
    AiTask.WRITE_SCENARIO: AiBucket.SCENARIO,
    AiTask.REPAIR_SCENARIO: AiBucket.SCENARIO,
    AiTask.PLAN_CHECK: AiBucket.SCENARIO,
    AiTask.REMEDIATION_PLAN: AiBucket.REMEDIATION,
    AiTask.SERVICE_MAPPER: AiBucket.SERVICE_MAPPER,
    AiTask.LINK_CONTROLS: AiBucket.CONTROLS,
    AiTask.PICK_CONTROLS: AiBucket.CONTROLS,
    AiTask.MITRE_ACTOR_SELECTION: AiBucket.SCENARIO,
    AiTask.MITRE_PLAN: AiBucket.SCENARIO,
    AiTask.MITRE_WRITE: AiBucket.SCENARIO,
}
#: An embedding or rerank call's part, by the job stage that made it.
SEARCH_STAGE_BUCKETS: Final[dict[str, AiBucket]] = {
    TaskName.FIND_THREATS: AiBucket.THREATS,
    TaskName.WRITE_SCENARIOS: AiBucket.SCENARIO,  # evidence search
    TaskName.MAP_CONTROLS: AiBucket.CONTROLS,
    TaskName.WRITE_PLAN: AiBucket.CONTROLS,  # the plan's controls matched
    TaskName.MAP_SERVICES: AiBucket.SERVICE_MAPPER,  # catalog search
    TaskName.LINK_MITIGATIONS: AiBucket.CONTROLS,  # each mitigation's candidate controls
}

#: Each module's parts, in report order: a report lists every one, 0 when it made no call.
MODULE_BUCKETS: Final[dict[str, tuple[AiBucket, ...]]] = {
    Module.THREAT_SCENARIOS: (AiBucket.THREATS, AiBucket.SCENARIO, AiBucket.CONTROLS),
    Module.REMEDIATION: (AiBucket.REMEDIATION, AiBucket.CONTROLS),
    Module.SERVICE_MAPPER: (AiBucket.SERVICE_MAPPER,),
}


def ai_bucket(task: str, job_task: str | None) -> AiBucket:
    """The part a call is counted in: a chat call's by its task, a search call's by its job stage; shared
    when neither says."""
    return CHAT_TASK_BUCKETS.get(task) or SEARCH_STAGE_BUCKETS.get(job_task or "", AiBucket.SHARED)


class AiUsageGroup(StrEnum):
    """What a totals report adds up by (?group_by=): a time step in the caller's time zone, or a row field."""

    HOUR = "hour"
    DAY = "day"
    MONTH = "month"
    MODULE = "module"
    API = "api"
    BUCKET = "bucket"
    TASK = "task"
    MODEL = "model"
    ENTITY_ID = "entity_id"
    CLIENT_ID = "client_id"


#: Each time step's text in a totals report ($dateToString formats).
GROUP_TIME_FORMATS: Final[dict[str, str]] = {
    AiUsageGroup.HOUR: "%Y-%m-%dT%H:00",
    AiUsageGroup.DAY: "%Y-%m-%d",
    AiUsageGroup.MONTH: "%Y-%m",
}


class AiUsageLimits:
    ROLLUP_EVERY_SECONDS: Final = 300  # beat sends the hourly add-up this often (maintenance queue)
    ROLLUP_CHUNK_SECONDS: Final = 120  # a day of the add-up's MongoDB time
    REPORT_SECONDS: Final = 30  # one report's MongoDB time; over it, 503
    REPORTS_AT_ONCE: Final = 2  # reports one API process computes at once, off the UI routes' threads
    REPORT_CACHE_SECONDS: Final = 60  # named in the frozen Swagger text
    REPORT_CACHE_KEY: Final = "tsg:ai_usage:report:{digest}"  # pinned name (tests/contract/tsg_names.json)
    DEFAULT_SPAN_DAYS: Final = 30  # a totals report with no `since`
    MAX_SPAN_DAYS: Final = 366  # the longest totals report or request list
    MAX_GROUPS: Final = 10_000  # the most rows a totals report returns
    PAGE_SIZE_DEFAULT: Final = 50
    PAGE_SIZE_MAX: Final = 500
    COPY_DAY_SECONDS: Final = 600  # copy-texts copies a day of call texts at a time, each within this
    REPORT_YEARS: Final = (2000, 9000)  # a report's since and until fall within these years
    REPORT_SLOT_WAIT_SECONDS: Final = 2  # a report waits this long for a free place, then 503


class AiUsageLogEvent(StrEnum):
    ROW_SPILLED = "ai.usage_row_spilled"  # a usage row MongoDB did not take: the whole row, to replay
    EXPIRY_FOUND = "ai.usage_expiry_found"  # a never-delete collection had an expiring index: dropped
    COMPRESSION_NOT_APPLIED = "ai.usage_compression_not_applied"  # created by another process, or no zstd
    ROLLUP_DONE = "ai.usage_rollup_done"


class AiUsageMessage(StrEnum):
    NEVER_DELETED = "{collection} is never deleted: AI usage is kept for good."
    SPAN_TOO_LONG = "The range is {days} days; at most {max_days} days are allowed."
    SPAN_EMPTY = "`since` must be before `until`."
    TZ_UNKNOWN = "Unknown time zone '{tz}'."
    TZ_NOT_WHOLE_HOURS = "Time zone '{tz}' is not a whole number of hours from UTC; totals are kept per hour."
    CALLS_NEED_SCOPE = "Give `request_id` or `session_id`."
    BAD_CURSOR = "`after` is not a cursor this list returned."
    REQUEST_NOT_FOUND = "No AI usage is recorded for request '{request_id}'."
    REPORTS_BUSY = "AI usage reports are busy right now; try again in a few seconds."
    MONGO_TOO_SLOW = (
        "MongoDB did not answer in time ({error}). Rows already stored stay stored and the next 5-minute "
        "add-up counts them; run this again to count them now."
    )
    YEAR_OUT_OF_RANGE = "A report's dates must fall within the years {first} to {last}."
