"""Statuses, error codes and messages, HTTP and storage names, timeouts and limits shared by every layer."""

from enum import StrEnum
from typing import Final


class Env(StrEnum):
    DEV = "dev"
    UAT = "uat"
    PROD = "prod"


class Status(StrEnum):
    """One status vocabulary for a run, a scenario, its controls and a remediation."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"  # stopped by its owner (G214): never claimed, re-sent or retried; resumable


class Decision(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class Step(StrEnum):
    """Where a run is (its status says how it is doing there)."""

    THREATS = "threats"
    SCENARIOS = "scenarios"
    CONTROLS = "controls"  # never stored: read while a done run still maps controls


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "validation_error"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"
    INTERNAL_ERROR = "internal_error"
    JOB_ABANDONED = "job_abandoned"  # its worker stopped renewing the lease Lease.MAX_ATTEMPTS times
    # A job's own final errors (JobFailed): the run reports them; a retry cannot change them.
    PLAN_REFUSED = "plan_refused"  # the asset's facts cannot be planned (e.g. a system squeezed out)
    ACTOR_LIBRARY_EMPTY = "actor_library_empty"  # no live threat actor: no scenario can name an attacker
    GENERATION_FAILED = "generation_failed"
    INVALID_PLAN = "invalid_plan"
    CONTROL_LIBRARY_EMPTY = "control_library_empty"
    # An AI answer no retry can fix (wrong-size or non-finite vectors, rerank scores outside 0-1): the model
    # profile or the provider's settings are wrong; the operator fixes them (G112).
    AI_ANSWER_UNUSABLE = "ai_answer_unusable"
    # The AI gateway refused the key, the permission or the model name: a setting to fix, not to retry.
    AI_MISCONFIGURED = "ai_misconfigured"
    # A path's threat or acting attacker was retired from the library after the plan was made (owner,
    # 2026-10-10; spec v4.0 §7.4.1): its scenario is not written.
    LIBRARY_RECORD_RETIRED = "library_record_retired"
    # G229 (owner 2026-10-13): with external intelligence on, no evidence found for the path's threat (after
    # the alternative search): its scenario is not written, and a reserve path may take its place.
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    # A regenerated version still broke a fixed rule after its rewrite: kept hidden for audit, the old version
    # stays current (BUILD_PLAN S41).
    SCENARIO_BLOCKED = "scenario_blocked"
    # The server is set up wrongly (e.g. the asset procedure lacks a column a setting names): the operator
    # fixes it; a retry cannot.
    SETUP_ERROR = "setup_error"


class ErrorMessage(StrEnum):
    """Every app-wide exception message (domain messages are their own enums below)."""

    IDENTITY_REQUIRED = "An API key and the user, entity and tenant headers are required."
    API_KEY_INVALID = "The API key is invalid or revoked."
    ADMIN_DISABLED = "Admin endpoints are disabled on this deployment."
    ADMIN_KEY_INVALID = "The admin key is missing or wrong."
    SQL_UNREACHABLE = "The library database is unreachable."
    MONGO_UNREACHABLE = "The scenario database is unreachable."
    REDIS_UNREACHABLE = "The queue and live-update service is unreachable."
    AI_UNREACHABLE = "The AI service is busy or unreachable. Try again shortly."
    AI_ANSWER_UNREADABLE = "The AI answer for '{task}' was not a JSON object."
    AI_REPLY_NOT_A_JSON_OBJECT = "The reply was not one JSON object."  # a re-ask problem line
    AI_ANSWER_REJECTED = "The AI answer for '{task}' was still wrong after one re-ask: {problems}"
    AI_ANSWER_TRUNCATED = "The AI answer for '{task}' from '{model}' was cut off at its length limit."
    AI_PROMPT_TOO_LONG = "The prompt for '{task}' has {chars} characters; the model takes at most {limit}."
    AI_BUSY = "Every AI slot stayed busy for {seconds} s. Try again shortly."
    # The evidence reranker's queue, not the AI slots (G218): the threat goes without evidence.
    RERANK_BUSY = "The evidence reranker stayed busy for {seconds} s: this threat goes without evidence."
    MODEL_PROFILE_MISSING = "No profile for AI model '{model}': add it to app/ai/profiles.py or fix .env."
    EMBEDDING_SIZE_MISMATCH = (
        "Embedding model '{model}' returned {received} numbers per text, not {expected}."
    )
    AI_ANSWER_INCOMPLETE = "The {task} answer from '{model}' did not match its {expected} inputs one to one."
    EMBEDDING_NOT_FINITE = (
        "Embedding model '{model}' returned a vector with a missing, infinite or all-zero value: it cannot "
        "be compared with any other."
    )
    RERANK_SCORE_OUT_OF_RANGE = (
        "Rerank model '{model}' scored {score}, outside 0-1: its provider returns raw scores, not "
        "probabilities (check the proxy's rerank settings)."
    )
    FIELDS_INVALID = "One or more fields are invalid."
    REQUEST_TOO_LARGE = "The request body is larger than the allowed {limit} bytes."
    EVENT_HUB_SILENT = (
        "Redis answered nothing for {seconds} s, not even PING: the live-update connection is lost."
    )
    JOB_ABANDONED = "The job stopped responding {attempts} times and was given up."
    JOB_NEVER_STARTED = "The job was sent {sends} times and never started, so it was given up."
    WORKER_METRICS_PORT_BUSY = (
        "Worker metrics port {port} is in use: set CII_WORKER_METRICS_PORT to a free port."
    )
    WORKER_POOL_UNSUPPORTED = (
        "Worker pool '{pool}' is not supported: start the worker with --pool=threads (or solo to debug)."
    )
    WORKER_START_FAILED = "The worker cannot start: {reason}"
    CORS_WILDCARD_OUTSIDE_DEV = (
        "CII_CORS_ORIGINS may not contain * outside dev: list the platform UI origins."
    )
    ADMIN_KEY_TOO_SHORT = "CII_ADMIN_API_KEY must be at least {minimum} characters outside dev."
    # What a scenario gets (owner 2026-10-13, G225-G226): a setting that cannot work stops start-up.
    COUNTRY_UNKNOWN = (
        "THREAT_CONTEXT_COUNTRY={value} is not a country this app knows the places of; set one of: {known}."
    )
    CONTROL_COUNT_INVALID = (
        "CONTROL_CANDIDATES ({candidates}) must be at least MAX_CONTROLS ({most}), and MAX_CONTROLS at least "
        "MIN_CONTROLS ({least})."
    )
    CONTROL_THRESHOLD_AS_FRACTION = (
        "{setting}={value} reads as {value} on the 0-100 scale, which keeps almost every control: write "
        "{percent:g} for {value}."
    )
    WORD_LIMIT_INVALID = "{setting}={value!r} must be two whole numbers, min-max, with 1 <= min <= max."
    PATH_NOT_WRITABLE = "Attack path {path_id} cannot be written: {problem}."
    CONTROL_LIBRARY_EMPTY = "The control library has no active control."
    PATH_AI_UNAVAILABLE = "The AI service did not answer for this attack path in {tries} tries."
    EVIDENCE_NOT_FOUND = (
        "No external intelligence supports this attack ({searches} search(es) made): it is not written "
        "without evidence."
    )
    EVIDENCE_SEARCH_UNAVAILABLE = "The evidence search could not be made for this attack path: {reason}."
    AI_MISCONFIGURED = (
        "The AI gateway refused model '{model}' ({error}, HTTP {status}): check the model name, the key and "
        "its permissions in the settings."
    )
    REGENERATE_BLOCKED = (
        "The new version still broke a fixed rule after its rewrite ({codes}): it is kept for audit only, "
        "and this version stays current."
    )
    UNEXPECTED = "Unexpected error. Quote the X-Request-Id header when reporting it."
    # A background job has no request id: its log lines carry the run's id (record_id).
    JOB_UNEXPECTED = "Unexpected error. Quote run id {record_id} when reporting it."


class Problem:
    """RFC 9457 problem response fixed parts."""

    TYPE: Final = "about:blank"
    MEDIA_TYPE: Final = "application/problem+json"
    # The WWW-Authenticate challenge of a 401: business calls send X-API-Key, admin calls X-Admin-Key.
    AUTH_CHALLENGE: Final = 'ApiKey realm="tsg", header="X-API-Key"'


class Header(StrEnum):
    API_KEY = "X-API-Key"
    USER_ID = "X-User-Id"
    ENTITY_ID = "X-Entity-Id"
    TENANT_ID = "X-Tenant-Id"
    ADMIN_KEY = "X-Admin-Key"
    IDEMPOTENCY_KEY = "Idempotency-Key"
    REQUEST_ID = "X-Request-Id"


class Collection(StrEnum):
    SESSIONS = "tsg_sessions"
    SCENARIOS = "tsg_scenarios"
    API_CLIENTS = "tsg_api_clients"
    EMBEDDINGS = (
        "tsg_embeddings"  # the library's vectors, with what each one is (app/data_access/embeddings.py)
    )
    QUERY_VECTORS = "tsg_query_vectors"  # search queries' vectors, kept Cache.QUERY_VECTOR_DAYS
    AI_CALLS = "tsg_ai_calls"
    AUDIT = "tsg_audit"
    REMEDIATIONS = "tsg_remediations"  # one remediation plan per scenario, with its versions (M11)
    ADMIN_JOBS = "tsg_admin_jobs"  # admin jobs (#18 embeddings build), kept AdminJobs.KEEP_DAYS
    INTEL = "tsg_intel"  # external intelligence records, one version per change
    EXTERNAL_FEED_STATUS = "tsg_external_feed_status"  # per source: last refresh, checkpoint; the switch
    EXTERNAL_INTELLIGENCE_SNAPSHOTS = "tsg_external_intelligence_snapshots"  # built snapshots, one active


class Dependency(StrEnum):
    MONGO = "mongo"
    SQL = "sql"
    REDIS = "redis"


class Timeouts:
    """Every network wait is bounded: an unbounded one holds a worker thread for ever when a store hangs."""

    MONGO_MS: Final = 5_000  # find a server / open a connection
    MONGO_SOCKET_MS: Final = 30_000  # one network wait inside an operation
    SQL_CONNECT_SECONDS: Final = 5  # log in; short, so an outage answers 503 quickly
    SQL_QUERY_SECONDS: Final = 30  # one procedure call
    REDIS_SECONDS: Final = 5  # connect and each command
    # A pooled Redis connection idle this long is PINGed before use: one a firewall or load balancer dropped
    # while idle is replaced, instead of failing the next publish or heartbeat after REDIS_SECONDS.
    REDIS_HEALTH_CHECK_SECONDS: Final = 30
    READY_CHECK_SECONDS: Final = 5  # /ready waits at most this for its checks; a slower one counts as down
    # A finished check is reused this long, so public /ready and /metrics callers cannot multiply store pings.
    # Below the 10 s readiness-probe period: every probe still gets a fresh result.
    READY_CHECK_REUSE_SECONDS: Final = 2
    RECORD_WRITE_SECONDS: Final = 5  # an audit or AI-call record write never holds an answer longer than this


class Cache:
    API_KEY_TTL_SECONDS: Final = (
        60  # number of seconds to cache an API key, before revalidating it  # noqa: E501
    )
    LIBRARY_STAMP_EVERY_SECONDS: Final = (
        60  # number of seconds to cache the library stamp, before revalidating it  # noqa: E501
    )
    # How often the maintenance worker computes vectors for new library rows, ahead of the first search.
    LIBRARY_INDEXES_EVERY_SECONDS: Final = 1_800
    # A search query's vector is kept this long: query texts are one-off, and without an expiry the store
    # would grow by every query ever asked.
    QUERY_VECTOR_DAYS: Final = 14
    # A library vector no row uses any more (its text changed, its row was deleted, the model changed) is kept
    # this long as the row's history, then deleted; as long as the audit trail (Audit.KEEP_DAYS).
    RETIRED_VECTOR_DAYS: Final = 365


class Limits:
    MIN_ADMIN_KEY_CHARS: Final = 32  # outside dev: a shorter admin key is refused at start-up
    # X-User-Id / X-Tenant-Id: stored in records and audit entries and logged, so bounded (422 above it).
    # 256 holds any e-mail address (at most 254 characters), the longest user id the platform sends.
    MAX_IDENTITY_CHARS: Final = 256
    MAX_IDEMPOTENCY_KEY_CHARS: Final = 200  # an Idempotency-Key header longer than this is refused (422)
    MAX_SQL_INT: Final = 2_147_483_647  # SQL Server INT: the largest id a stored procedure accepts
    PAGE_SIZE_DEFAULT: Final = 50  # default number of items to return in a paginated response  # noqa: E501
    PAGE_SIZE_MAX: Final = 500  # maximum number of items to return in a paginated response  # noqa: E501
    RETRY_AFTER_SECONDS: Final = 5  # the Retry-After of every 503: when a caller should try again


class Tracing:
    """The step trace's bounds (DEBUG_STEP_OUTPUT, app/core/tracing.py): what one logged value may show."""

    PREVIEW_CHARS: Final = 1_000  # a text value is clipped here, after redaction
    PREVIEW_ITEMS: Final = 3  # a longer list shows its count and its first items
    PREVIEW_KEYS: Final = 40  # a mapping or object shows at most this many fields
    PREVIEW_DEPTH: Final = 4  # nested deeper than this, a value shows only its type
    DETAIL_TOP: Final = 10  # entries a ranked inner record keeps by default (DEBUG_STEP_TOP)
    DETAIL_TEXT_CHARS: Final = 80  # a query or reason shown inside an inner record is cut here
    DETAIL_MAX_RECORDS: Final = 30  # per-item inner records one step logs at most (actor rankings)
