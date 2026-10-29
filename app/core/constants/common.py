"""Statuses, store names and limits, AI calls and log events shared by every layer (waits: timing.py)."""

from enum import StrEnum
from typing import Final

from app.core.ai_tuning_settings import TUNING
from app.core.prompts import PROMPTS


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
    CANCELLED = "cancelled"  # stopped by its owner: never claimed, re-sent or retried; resumable


class Decision(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class Step(StrEnum):
    """Where a run is (its status says how it is doing there)."""

    THREATS = "threats"
    SCENARIOS = "scenarios"
    CONTROLS = "controls"  # never stored: read while a done run still maps controls


class Collection(StrEnum):
    SERVICE_MAPPINGS = "tsg_service_mappings"
    SESSIONS = "tsg_sessions"
    SCENARIOS = "tsg_scenarios"
    API_CLIENTS = "tsg_api_clients"
    EMBEDDINGS = "tsg_embeddings"  # the library's vectors
    QUERY_VECTORS = "tsg_query_vectors"  # search queries' vectors, kept Cache.QUERY_VECTOR_DAYS
    AI_CALLS = "tsg_ai_calls"
    AUDIT = "tsg_audit"
    REMEDIATIONS = "tsg_remediations"  # one remediation plan per scenario, with its versions
    ADMIN_JOBS = "tsg_admin_jobs"
    INTEL = "tsg_intel"  # external intelligence records, one version per change
    EXTERNAL_FEED_STATUS = "tsg_external_feed_status"  # per source: last refresh, checkpoint; the switch
    EXTERNAL_INTELLIGENCE_SNAPSHOTS = "tsg_external_intelligence_snapshots"  # built snapshots, one active
    SQL_OPERATIONS = "tsg_sql_operations"  # one record per SQL Server write, so a lost answer is reconciled


class SqlOperationStatus(StrEnum):
    """Where one SQL Server write stands (tsg_sql_operations.status)."""

    PENDING = "pending"  # written before the call: the call runs now, or its process died during it
    DONE = "done"  # applied: its stored result answers every retry, with no SQL call
    NOT_APPLIED = "not_applied"  # SQL Server answered with an error: rolled back, a retry runs it again
    REQUIRES_RECONCILIATION = "requires_reconciliation"  # sent, answer lost: the next attempt replays it


class SqlOperations:
    KEEP_DAYS: Final = 30  # a finished record is deleted this long after it finished (TTL on finished_at)
    PENDING_SECONDS: Final = 60  # above connect + query timeouts: an older pending call has died


class Dependency(StrEnum):
    MONGO = "mongo"
    SQL = "sql"
    REDIS = "redis"


class Limits:
    MIN_ADMIN_KEY_CHARS: Final = 32  # outside dev, a shorter admin key stops start-up
    MAX_IDENTITY_CHARS: Final = 256  # X-User-Id / X-Tenant-Id: any e-mail address fits
    MAX_IDEMPOTENCY_KEY_CHARS: Final = 200
    MAX_SQL_INT: Final = 2_147_483_647  # SQL Server INT: the largest id a procedure accepts
    PAGE_SIZE_DEFAULT: Final = 50
    PAGE_SIZE_MAX: Final = 500
    RETRY_AFTER_SECONDS: Final = 5  # the Retry-After of every 503


class AiOutcome(StrEnum):
    """tsg_ai_calls_total{outcome}."""

    OK = "ok"
    UNAVAILABLE = "unavailable"  # the provider busy or unreachable, after the retries
    UNREADABLE = "unreadable"  # an answer that cannot be used
    TRUNCATED = "truncated"  # an answer cut off at its length limit
    ERROR = "error"  # anything else: a refused key, a bad request, a local model that would not load


class AiOutage(StrEnum):
    """Why the AI service did not answer: the `reason` of a retry notice and of a stage that failed for it."""

    DOWN = "ai_down"  # it answered with a server error (HTTP 500, 502)
    UNREACHABLE = "ai_unreachable"  # no connection: refused, DNS, proxy or TLS
    BUSY = "ai_busy"  # too many requests (HTTP 429), overloaded (HTTP 503), or no local AI slot free
    TIMED_OUT = "ai_timed_out"  # no answer within the time limit


#: A failure card's message when an AI outage cost its path on the job's last try: the outage, then the tries.
AI_PATH_OUTAGE_MESSAGE: Final = "{outage} This attack path got no answer in {tries} tries."

#: HTTP statuses telling the outage when the error's class does not: a timeout, or an overloaded provider.
AI_TIMED_OUT_STATUSES: Final = frozenset({408, 504, 524, 598, 599})
AI_BUSY_STATUSES: Final = frozenset({503, 529})

#: What the UI is told for each outage: a retry notice's message, then the failed stage's.
AI_OUTAGE_MESSAGES: Final = {
    AiOutage.DOWN: "The AI service is down: it answered with a server error.",
    AiOutage.UNREACHABLE: "The AI service cannot be reached: no connection could be made.",
    AiOutage.BUSY: "The AI service is busy: overloaded or too many requests right now.",
    AiOutage.TIMED_OUT: "The AI service timed out: it did not answer in time.",
}


class AiTask(StrEnum):
    SERVICE_MAPPER = "service_mapper"
    """Why an AI model is called (metrics label and tsg_ai_calls field)."""

    RELEVANCE_GATE = "relevance_gate"
    GAP_FILL = "gap_fill"
    THREAT_ACTIONS = "threat_actions"  # the actions a threat's name states, for the writer and reviewer
    WRITE_SCENARIO = "write_scenario"
    REPAIR_SCENARIO = "repair_scenario"  # a draft written again for actions not carried out
    PLAN_CHECK = "plan_check"  # does the written scenario carry out its plan
    REMEDIATION_PLAN = "remediation_plan"
    EMBED = "embed"
    RERANK = "rerank"


class PromptVersion:
    """One number for every AI prompt's label: the version in app/prompts.toml."""

    NUMBER: Final[int] = PROMPTS["version"]
    PLANNER: Final = f"planner-{NUMBER}"  # plan.prompt_version ([scenario.gate], [scenario.gap_fill])
    SCENARIO_WRITER: Final = f"scenario writer-{NUMBER}"  # content.prompt_version (writer, reviewer)
    SCENARIO_WRITER_EVIDENCE: Final = f"scenario writer-evidence-{NUMBER}"  # a story's content.prompt_version
    REMEDIATION: Final = f"remediation-{NUMBER}"  # every remediation plan version


#: Temperature per chat task: 0.0 for a repeatable answer; None = the provider's default, so a new action
#: (a new epoch) gets a new answer, while a re-delivery of the same job reads its accepted answer back.
CHAT_TEMPERATURES: Final[dict[AiTask, float | None]] = {
    AiTask.SERVICE_MAPPER: 0.0,
    AiTask.RELEVANCE_GATE: 0.0,
    AiTask.GAP_FILL: 0.0,
    AiTask.THREAT_ACTIONS: 0.0,
    AiTask.PLAN_CHECK: 0.0,
    AiTask.REMEDIATION_PLAN: 0.0,
    AiTask.WRITE_SCENARIO: None,
    AiTask.REPAIR_SCENARIO: None,
}

#: Most answer tokens per chat task (CII_ANSWER_TOKENS_<TASK>), counted against the AI service's budget while
#: a question runs; an answer cut off at it is asked again at the model's limit, as a thinking model is.
CHAT_MAX_OUTPUT_TOKENS: Final[dict[AiTask, int]] = {
    AiTask.RELEVANCE_GATE: TUNING.answer_tokens_relevance_gate,
    AiTask.GAP_FILL: TUNING.answer_tokens_gap_fill,
    AiTask.THREAT_ACTIONS: TUNING.answer_tokens_threat_actions,
    AiTask.WRITE_SCENARIO: TUNING.answer_tokens_write_scenario,
    AiTask.REPAIR_SCENARIO: TUNING.answer_tokens_repair_scenario,
    AiTask.PLAN_CHECK: TUNING.answer_tokens_plan_check,
    AiTask.REMEDIATION_PLAN: TUNING.answer_tokens_remediation_plan,
    AiTask.SERVICE_MAPPER: TUNING.answer_tokens_service_mapper,
}
#: A model served by the LiteLLM gateway; only those hosts skip the proxy when CII_AI_BYPASS_PROXY=true.
LITELLM_MODEL_PREFIX: Final = "litellm_proxy/"
#: Thinking off in the gateway models' chat templates (UAT probe, 2026-10-23): Kimi reads "thinking", GLM
#: "enable_thinking"; each template ignores the other. Its own reasoning_effort did not stop GLM thinking.
THINKING_OFF_TEMPLATE_KWARGS: Final = {"thinking": False, "enable_thinking": False}


class EmbeddingCorpus(StrEnum):
    """What a vector was made from (tsg_embeddings.corpus): each kind is embedded and searched on its own."""

    CONTROL = "control"
    THREAT = "threat"
    THREAT_ACTOR = "threat_actor"
    THREAT_TYPE = "threat_type"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    SERVICE = "service"


#: Each library corpus by the name the embeddings API reports it under.
LIBRARY_OF_CORPUS: Final = {
    EmbeddingCorpus.THREAT: "threats",
    EmbeddingCorpus.THREAT_TYPE: "threat_types",
    EmbeddingCorpus.THREAT_ACTOR: "actors",
    EmbeddingCorpus.CONTROL: "controls",
}

#: The table each corpus's rows come from (tsg_embeddings.sources[].table).
EMBEDDING_SOURCE_TABLE: Final[dict[EmbeddingCorpus, str]] = {
    EmbeddingCorpus.SERVICE: "onboarding_services",
    EmbeddingCorpus.CONTROL: "Control_Library",
    EmbeddingCorpus.THREAT: "Threat_Catalogue",
    EmbeddingCorpus.THREAT_ACTOR: "Threat_Actor",
    EmbeddingCorpus.THREAT_TYPE: "Threat_Type",
    EmbeddingCorpus.EXTERNAL_INTELLIGENCE: "tsg_intel",  # a Mongo collection, not a SQL table
}


class LogEvent(StrEnum):
    """Every log event name (domain.action)."""

    HTTP_REQUEST = "http.request"
    HTTP_APP_ERROR = "http.app_error"
    HTTP_UNHANDLED_ERROR = "http.unhandled_error"
    DEPENDENCY_UNAVAILABLE = "dependency.unavailable"
    MONGODB_TOPOLOGY = "mongodb.topology"  # at start: replica set or standalone, version, write concern
    REDIS_EVICTION_POLICY = "redis.eviction_policy"  # at start: maxmemory-policy, error unless noeviction
    MONGODB_VALIDATOR_NOT_APPLIED = "mongodb.validator_not_applied"  # an older server or no collMod right
    AI_CALL = "ai.call"
    AI_CALL_RECORD_FAILED = "ai.call_record_failed"
    AI_CALL_REFUSED = "ai.call_refused"  # a key, permission or model name the gateway refused
    AI_CALL_UNAVAILABLE = "ai.call_unavailable"
    AI_ANSWER_REUSED = "ai.answer_reused"  # this job got this exact conversation's answer before: no call
    AI_ANSWER_LOOKUP_FAILED = "ai.answer_lookup_failed"  # the AI is asked instead
    AI_FIRST_ANSWER_KEPT = "ai.first_answer_kept"  # a re-ask failed: the usable first answer, faults and all
    AI_GATEWAY_ROUTE = "ai.gateway_route"
    AI_REQUEST_RATE_BUSY = "ai.request_rate_busy"
    AI_SLOTS_BUSY = "ai.slots_busy"
    AI_SLOT_FREE_FAILED = "ai.slot_free_failed"
    # Redis failed: at cap 0 AI calls go ahead uncounted and unlimited, and requests unspaced; at any cap a
    # 429 or an answer could not change the limit
    AI_SLOTS_UNTRACKED = "ai.slots_untracked"
    AI_LIMIT_CUT = "ai.limit_cut"  # a gateway 429 set the limit on AI calls in flight
    LIBRARY_RELOADED = "library.reloaded"
    LIBRARY_RETIRED_CONTROLS_MISSING = "library.retired_controls_missing"  # an old tsg_GetControlLibrary
    LIBRARY_THREAT_ASSET_TYPE_MISSING = "library.threat_asset_type_missing"  # an old tsg_GetThreatLibrary
    LIBRARY_ASSET_TYPE_UNKNOWN = "library.asset_type_unknown"  # an AssetType not IT, OT or IT\OT
    CONTEXT_SERVICE_NOT_LINKED = "context.service_not_linked"  # the asked service is used anyway
    CONTEXT_OPTION_VALUE_NOT_FOUND = "context.option_value_not_found"  # a stored code with no name
    LIBRARY_CHECK_FAILED = "library.check_failed"
    LIBRARY_INDEXES_BUILT = "library.indexes_built"
    LIBRARY_INDEXES_BUILD_FAILED = "library.indexes_build_failed"
    PLANNER_THREATS_NOT_JUDGED = "planner.threats_not_judged"  # a gate or gap-fill reply skipped
    PLANNER_FUNNEL = "planner.funnel"  # a plan made: how many candidates entered and left each stage
    PLANNER_THREAT_NOT_PLANNED = "planner.threat_not_planned"  # no linked attacker, or none plausible
    WRITER_PLAN_CHECK_NOT_MADE = "writer.plan_check_not_made"
    WRITER_THREAT_ACTIONS_NOT_SPLIT = "writer.threat_actions_not_split"  # the writer and reviewer split it
    WRITER_SCENARIO_REPAIRED = "writer.scenario_repaired"  # "fixed", or "kept_first" with any error
    WRITER_SCENARIO_SAVED = "writer.scenario_saved"
    WRITER_PATH_FAILED = "writer.path_failed"
    CONTROLS_MAPPED = "controls.mapped"
    CONTROLS_NOT_MAPPED = "controls.not_mapped"
    CONTROLS_MAP_FAILED = "controls.map_failed"
    WRITER_OUTAGE_SETTLED = "writer.outage_settled"  # an outage only some paths kept hitting: failure cards
    WRITER_PATH_ABANDONED = "writer.path_abandoned"
    WRITER_REGENERATE_FAILED = "writer.regenerate_failed"  # the old version stays current
    EMBEDDINGS_RETIRED = "embedding.retired"
    EMBEDDING_STORED_SIZE_WRONG = "embedding.stored_size_wrong"
    JOB_STARTED = "job.started"  # every task: its id, record/job id, worker and the API request that sent it
    JOB_FINISHED = "job.finished"  # the same with its outcome and seconds
    WORKER_START_FAILED = "worker.start_failed"  # a worker that cannot start says why before it exits
    CONTROLS_SWEPT = "controls.swept"  # the controls sweep's requeued and abandoned mappings, by run
    JOB_NOT_CLAIMED = "job.not_claimed"  # with its reason: missing, other_epoch, other_task, not_due, ...
    CLOCK_OFF = "clock.off"  # this pod's clock differs from MongoDB's by more than Clock.WARN_OVER_SECONDS
    JOB_LEASE_LOST = "job.lease_lost"
    JOB_STOPPED_BY_OWNER = "job.stopped_by_owner"  # its run or plan was cancelled or deleted
    JOB_LEASE_RENEW_FAILED = "job.lease_renew_failed"
    JOB_RETRY_SCHEDULED = "job.retry_scheduled"
    JOB_WAITING = "job.waiting"  # given back to look again: another job holds what it needs (not an outage)
    JOB_FAILED = "job.failed"
    JOB_FAILURE_NOT_SAVED = "job.failure_not_saved"  # MongoDB down: the reaper settles the job later
    JOB_UNEXPECTED_ERROR = "job.unexpected_error"  # a bug: logged with its traceback
    JOB_STALLED = "job.stalled"  # no lease check for Lease.STALL_SECONDS: it stopped renewing its lease
    JOB_HANDED_BACK = "job.handed_back"  # a stopping worker queued its running job again, no attempt used
    JOB_REQUEUED = "job.requeued"
    JOB_SEND_FAILED = "job.send_failed"
    JOB_QUEUE_SIZE_UNKNOWN = "job.queue_size_unknown"
    JOB_REAP_FAILED = "job.reap_failed"
    WORKER_METRICS_SERVING = "worker.metrics_serving"
    WORKER_RERANKER_PRELOAD_FAILED = "worker.reranker_preload_failed"  # the first rerank loads it instead
    WORKER_HEARTBEAT_FAILED = "worker.heartbeat_failed"
    WORKER_JOB_HUNG = "worker.job_hung"  # a job thread ignored its lost lease: the liveness probe restarts it
    WORKER_NONE_ONLINE = "worker.none_online"
    WORKERS_UNKNOWN = "worker.count_unknown"
    EVENT_PUBLISH_FAILED = "event.publish_failed"
    EVENT_HUB_RECONNECTING = "event.hub_reconnecting"
    EVENT_HUB_FAILED = "event.hub_failed"
    AUDIT_RECORDED = "audit.recorded"
    AUDIT_WRITE_FAILED = "audit.write_failed"
    EXTERNAL_INTELLIGENCE_REFRESHED = "external_intelligence.refreshed"
    EXTERNAL_INTELLIGENCE_SOURCE_FAILED = "external_intelligence.source_failed"
    EXTERNAL_INTELLIGENCE_CLAIM_LOST = "external_intelligence.claim_lost"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_ACTIVATED = "external_intelligence.snapshot_activated"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_SUPERSEDED = "external_intelligence.snapshot_superseded"
    EXTERNAL_INTELLIGENCE_SNAPSHOT_BUILD_FAILED = "external_intelligence.snapshot_build_failed"
    EXTERNAL_INTELLIGENCE_NO_DATA = "external_intelligence.no_data_yet"  # once per process
    EXTERNAL_INTELLIGENCE_EVIDENCE_SEARCH_FAILED = "external_intelligence.evidence_search_failed"
    EXTERNAL_INTELLIGENCE_SWITCH_CHANGED = "external_intelligence.switch_changed"
    EXTERNAL_INTELLIGENCE_TEXT_QUARANTINED = "external_intelligence.text_quarantined"
    EXTERNAL_INTELLIGENCE_SENTENCES_REMOVED = "external_intelligence.sentences_removed"
