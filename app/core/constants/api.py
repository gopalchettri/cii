"""The API's errors, headers, keys, audit and Swagger groups, and the service mapper's values."""

from enum import StrEnum
from typing import Final


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "validation_error"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNAVAILABLE = "unavailable"
    INTERNAL_ERROR = "internal_error"
    JOB_ABANDONED = "job_abandoned"  # its worker stopped renewing the lease Lease.MAX_ATTEMPTS times
    # A job's own final errors (JobFailed): a retry cannot change them.
    PLAN_REFUSED = "plan_refused"  # the asset's facts cannot be planned
    ACTOR_LIBRARY_EMPTY = "actor_library_empty"  # no type links a live threat actor: no attacker to name
    GENERATION_FAILED = "generation_failed"
    INVALID_PLAN = "invalid_plan"
    CONTROL_LIBRARY_EMPTY = "control_library_empty"
    AI_ANSWER_UNUSABLE = "ai_answer_unusable"  # no retry can fix it: the model profile or provider is wrong
    AI_MISCONFIGURED = "ai_misconfigured"  # the gateway refused the key, permission or model name
    LIBRARY_RECORD_RETIRED = "library_record_retired"  # a path's threat or attacker retired after planning
    EVIDENCE_NOT_FOUND = (
        "evidence_not_found"  # intelligence on and no evidence: a reserve path may replace it
    )
    SCENARIO_BLOCKED = "scenario_blocked"  # a regenerated version broke a fixed rule
    SETUP_ERROR = "setup_error"  # the server is set up wrongly: the operator fixes it, a retry cannot


class ErrorMessage(StrEnum):
    """Every app-wide exception message (domain messages have their own enums)."""

    IDENTITY_REQUIRED = "An API key and the user, entity and tenant headers are required."
    API_KEY_INVALID = "The API key is invalid or revoked."
    ADMIN_DISABLED = "Admin endpoints are disabled on this deployment."
    ADMIN_KEY_INVALID = "The admin key is missing or wrong."
    SQL_UNREACHABLE = "The library database is unreachable."
    SQL_DEADLOCK = "The library database chose this call as a deadlock victim and applied nothing."
    SQL_ANSWER_LOST = "The library database did not answer after the call was sent: its outcome is unknown."
    SQL_OPERATION_UNCONFIRMED = (
        "The library database did not confirm operation {operation_id}; retry the request to reconcile it."
    )
    SQL_OPERATION_IN_PROGRESS = "Operation {operation_id} is running now; try again shortly."
    MONGO_UNREACHABLE = "The scenario database is unreachable."
    UNIQUE_RULE_BROKEN = "The unique index '{index_name}' refused the write."
    NAMED_CONDITION_TAKES_TRUE = "The named condition '{name}' is applied with {name}=True only."
    WRITE_NEEDS_A_CONDITION = "An update or delete with no condition would change the whole collection."
    REDIS_UNREACHABLE = "The queue and live-update service is unreachable."
    AI_UNREACHABLE = "The AI service is busy or unreachable. Try again shortly."
    AI_ANSWER_REFUSED = "The AI answer for '{task}' was refused or malformed ({error})."
    AI_REPLY_NOT_A_JSON_OBJECT = "The reply was not one JSON object."  # a re-ask problem line
    AI_ANSWER_REJECTED = "The AI answer for '{task}' was still wrong after one re-ask: {problems}"
    AI_ANSWER_TRUNCATED = "The AI answer for '{task}' from '{model}' was cut off at its length limit."
    AI_PROMPT_TOO_LONG = "The prompt for '{task}' has {chars} characters; the model takes at most {limit}."
    AI_BUSY = "Every AI slot stayed busy for {seconds} s. Try again shortly."
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
    LOCAL_RERANKER_MISSING = (
        "CII_RERANK_BASE_URL is empty, so the reranker ({model}) runs on this machine, and it needs the "
        "sentence-transformers package, which this Python does not have: pip install -r requirements.txt, "
        "or set CII_RERANK_BASE_URL to a reranker service."
    )
    PROXY_URL_WITHOUT_SCHEME = (
        "CII_PROXY_URL must start with http:// or https://, for example http://10.61.192.2:8080 "
        "(empty = none)."
    )
    COUNTRY_UNKNOWN = (
        "THREAT_CONTEXT_COUNTRY={value} is not a country this app knows the places of; set one of: {known}."
    )
    CONTROL_COUNT_INVALID = (
        "CONTROL_CANDIDATES ({candidates}) must be at least MAX_CONTROLS ({most}), and MAX_CONTROLS at least "
        "MIN_CONTROLS ({least}) and NEAREST_CONTROLS ({nearest})."
    )
    CONTROL_THRESHOLD_AS_FRACTION = (
        "{setting}={value} reads as {value} on the 0-100 scale, which keeps almost every control: write "
        "{percent:g} for {value}."
    )
    WORD_LIMIT_INVALID = "{setting}={value!r} must be two whole numbers, min-max, with 1 <= min <= max."
    PATH_NOT_WRITABLE = "Attack path {path_id} cannot be written: {problem}."
    CONTROL_LIBRARY_EMPTY = "The control library has no active control."
    PATH_AI_UNAVAILABLE = "The AI service did not answer for this attack path in {tries} tries."
    EVIDENCE_NOT_FOUND = "No external intelligence supports this attack: it is not written without evidence."
    EVIDENCE_SEARCH_UNAVAILABLE = "The evidence search could not be made for this attack path: {reason}."
    AI_MISCONFIGURED = (
        "The AI gateway refused model '{model}' ({error}, HTTP {status}): check the model name, the key and "
        "its permissions in the settings."
    )
    REGENERATE_BLOCKED = (
        "The new version broke a fixed rule ({codes}): it is kept for audit only, "
        "and this version stays current."
    )
    UNEXPECTED = "Unexpected error. Quote the X-Request-Id header when reporting it."
    JOB_UNEXPECTED = (
        "Unexpected error. Quote run id {record_id} when reporting it."  # a job has no request id
    )
    PROCEDURE_NOT_ALLOWED = "{procedure!r} is not a TSG stored procedure: only StoredProcedure members run."
    SQL_VALUE_REFUSED = "The library database refused a value as out of range or already present."
    SQL_PROCEDURE_BROKEN = (
        "A library database procedure is missing or refused its call: install scripts/sql/ on this database."
    )


class Problem:
    """RFC 9457 problem response fixed parts."""

    TYPE: Final = "about:blank"
    MEDIA_TYPE: Final = "application/problem+json"
    AUTH_CHALLENGE: Final = 'ApiKey realm="tsg", header="X-API-Key"'  # the WWW-Authenticate of a 401


class Header(StrEnum):
    API_KEY = "X-API-Key"
    USER_ID = "X-User-Id"
    ENTITY_ID = "X-Entity-Id"
    TENANT_ID = "X-Tenant-Id"
    ADMIN_KEY = "X-Admin-Key"
    IDEMPOTENCY_KEY = "Idempotency-Key"
    REQUEST_ID = "X-Request-Id"


class ApiTag(StrEnum):
    """The Swagger page's groups, in the order a tester uses them."""

    HEALTH = "1. Health"
    API_KEYS = "2. Set-up: API keys"
    EMBEDDINGS = "3. Set-up: library embeddings"
    INTELLIGENCE = "4. Set-up: external intelligence"
    RUNS = "5. Threat scenarios: runs"
    REVIEW = "6. Threat scenarios: review"
    REMEDIATION = "7. Remediation plans"
    JOBS = "8. My jobs"
    LIVE_UPDATES = "9. Live updates"
    CURATION = "10. Library curation"
    SERVICE_MAPPER = "11. Service mapper"


class AuditAction(StrEnum):
    """Every audited action (tsg_audit.action)."""

    KEY_MINTED = "key.minted"
    KEY_REVOKED = "key.revoked"
    RUN_STARTED = "run.started"
    MAPPING_STARTED = "mapping.started"
    MAPPING_REGENERATED = "mapping.regenerated"
    DEPENDENCY_REVIEWED = "mapping.dependency_reviewed"
    RUN_NEXT_SET = "run.next_set"
    RUN_REGENERATED = "run.regenerated"
    SCENARIOS_ACCEPTED = "scenario.accepted"
    SCENARIOS_REJECTED = "scenario.rejected"
    LIBRARY_PROMOTED = "library.promoted"
    PLAN_REQUESTED = "plan.requested"
    PLAN_COMPLETED = "plan.completed"  # the actor is the job
    LIBRARY_PROPOSED = "library.proposed"  # a hand-written scenario's new threat, pending a curator
    PLAN_REGENERATED = "plan.regenerated"
    PLAN_ACCEPTED = "plan.accepted"
    PLAN_REJECTED = "plan.rejected"
    LIBRARY_DECIDED = "library.decided"  # a curator approved or rejected pending threats
    ADMIN_JOB_STARTED = "admin.job_started"
    ADMIN_JOB_FINISHED = "admin.job_finished"  # the actor is the job
    RUN_CANCELLED = "run.cancelled"
    SESSION_DELETED = "session.deleted"  # a run removed for good, with its scenarios and plans
    PLAN_CANCELLED = "plan.cancelled"
    EXTERNAL_INTELLIGENCE_REFRESHED = "external_intelligence.refreshed"  # the actor is the job
    EXTERNAL_INTELLIGENCE_REFRESH_FAILED = "external_intelligence.refresh_failed"
    EXTERNAL_INTELLIGENCE_EVIDENCE_USED = "external_intelligence.evidence_used"  # one batch's search
    EXTERNAL_INTELLIGENCE_SWITCHED = "external_intelligence.switched"
    EXTERNAL_INTELLIGENCE_SOURCE_REVOKED = "external_intelligence.source_revoked"  # records, vectors purged
    EXTERNAL_INTELLIGENCE_SOURCE_APPROVED = "external_intelligence.source_approved"


class AuditTarget(StrEnum):
    """What kind of record an audited action changed (tsg_audit.target.type)."""

    API_CLIENT = "api_client"
    SESSION = "session"
    MAPPING = "mapping"
    SCENARIO = "scenario"
    REMEDIATION = "remediation"
    LIBRARY_THREAT = "library_threat"
    ADMIN_JOB = "admin_job"
    EXTERNAL_INTELLIGENCE_SOURCE = "external_intelligence_source"


class Audit:
    KEEP_DAYS: Final = 365  # tsg_audit retention (TTL on `at`)
    ADMIN_USER: Final = "admin"  # who an admin call is recorded as when it sends no X-User-Id


class ApiKey:
    PREFIX: Final = "ciip_"
    RANDOM_BYTES: Final = 32
    SHOWN_PREFIX_LENGTH: Final = 8


class ApiClientMessage(StrEnum):
    NAME_TAKEN = "An active API client named '{name}' already exists."
    NOT_FOUND = "API client '{client_id}' does not exist."


class MapperConflict(StrEnum):
    """The `reason` of a service mapper 409."""

    GENERATION_IN_PROGRESS = "generation_in_progress"


class MapperDecisionFailure(StrEnum):
    """Why one id of a relationship decision was not saved (the others still are)."""

    DEPENDENCY_NOT_FOUND = "dependency_not_found"
    DECISION_FINAL = "decision_final"


class MappingOverall(StrEnum):
    """Where a mapping's generation is (progress.overall)."""

    FAILED = "failed"  # the generation failed: `error` says why
    CANCELLED = "cancelled"
    GENERATING = "generating"  # queued or running: wait
    DONE = "done"  # its relationships can be decided (progress.relationships counts them)


class MapperMessage(StrEnum):
    AI_ANSWER_INVALID = "The AI answer did not satisfy the Service Mapper output contract."
    IDEMPOTENCY_KEY_CONFLICT = "This Idempotency-Key was already used for another mapping input."
    MAPPING_NOT_READY = "The mapping has not finished generating."
    DEPENDENCY_NOT_FOUND = "No such dependency in the current generation."
    NOTHING_TO_DECIDE = "Name at least one dependency_id in accept or reject."
    ACCEPTED_AND_REJECTED = "A dependency_id cannot be both accepted and rejected: {ids}."
    TOO_MANY_DECISIONS = "At most {limit} dependency ids per request."
    REQUIRED_VALUE_BLANK = "A required value cannot be blank."
    ENTITY_NAME_INVALID = "Each entity name must contain 1 to 255 characters."
    ENTITY_NAMES_REPEATED = "Entity names must be unique."
    CATALOG_RESULT_SETS = "The Service Mapper SQL procedures returned an unexpected number of result sets."
    CATALOG_ROW_INVALID = "The Service Mapper SQL catalog contains an invalid or inconsistent row."
    NOT_YOUR_ENTITY = "entity_id must be the caller's entity (the X-Entity-Id header)."
    MAPPING_NOT_FOUND = "No such mapping."
    ROUND_RUNNING = "A round is already running for this mapping."
    DECISION_FINAL = "This recommendation was already decided differently; decisions are final."


class MapperLimits:
    CANDIDATE_POOL: Final = 80
    MAX_DECISIONS: Final = 200  # ids per relationship decision: both directions at their largest count (100)
