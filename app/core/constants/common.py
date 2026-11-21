"""Statuses, store names, limits, waits, job modules and log events shared by every layer."""

from enum import StrEnum
from typing import Final

from app.core.ai_tuning_settings import TUNING
from app.core.constants.jobs import TaskName
from app.core.prompts import MITRE_PROMPTS, PROMPTS


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
    AI_CALLS = "tsg_ai_call_texts"  # kept for good: a name no older release gives an expiry
    AUDIT = "tsg_audit"
    REMEDIATIONS = "tsg_remediations"  # one remediation plan per scenario, with its versions
    ADMIN_JOBS = "tsg_admin_jobs"
    INTEL = "tsg_intel"  # external intelligence records, one version per change
    EXTERNAL_FEED_STATUS = "tsg_external_feed_status"  # per source: last refresh, checkpoint; the switch
    EXTERNAL_INTELLIGENCE_SNAPSHOTS = "tsg_external_intelligence_snapshots"  # built snapshots, one active
    SQL_OPERATIONS = "tsg_sql_operations"  # one record per SQL Server write, so a lost answer is reconciled
    ATTACK = "tsg_attack"  # the MITRE ATT&CK graph: groups, techniques, mitigations and their relationships
    CONTROL_LINKS = "tsg_control_links"  # per ATT&CK mitigation: the library controls that do what it says
    MITRE_ENTERPRISE_STIX = "tsg_mitre_enterprise_stix"  # the MITRE run's Enterprise STIX objects, one version
    MITRE_ICS_STIX = "tsg_mitre_ics_stix"  # the same for ICS


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
    """Why an AI model is called (metrics label, tsg_ai_call_texts and tsg_ai_usage field)."""

    RELEVANCE_GATE = "relevance_gate"
    GAP_FILL = "gap_fill"
    THREAT_ACTIONS = "threat_actions"  # the actions a threat's name states, for the writer and reviewer
    WRITE_SCENARIO = "write_scenario"
    REPAIR_SCENARIO = "repair_scenario"  # a draft written again for actions not carried out
    PLAN_CHECK = "plan_check"  # does the written scenario carry out its plan
    REMEDIATION_PLAN = "remediation_plan"
    LINK_CONTROLS = "link_controls"  # which library controls do what one ATT&CK mitigation says
    PICK_CONTROLS = "pick_controls"  # which shortlisted control reduces which sentence of a written set
    EMBED = "embed"
    RERANK = "rerank"
    MITRE_ACTOR_SELECTION = "mitre_actor_selection"  # which MITRE actors fit the asset, from all of them
    MITRE_PLAN = "mitre_plan"  # a MITRE run's attack paths over every technique
    MITRE_DUPLICATE_CHECK = "mitre_duplicate_check"  # which new MITRE paths repeat a planned one in meaning
    MITRE_WRITE = "mitre_write"  # one MITRE set's scenarios, one per attack path


class PromptVersion:
    """One number for every AI prompt's label: the version in app/prompts.toml."""

    NUMBER: Final[int] = PROMPTS["version"]
    SCENARIO_WRITER: Final = f"scenario writer-{NUMBER}"  # content.prompt_version (writer, reviewer)
    SCENARIO_WRITER_EVIDENCE: Final = f"scenario writer-evidence-{NUMBER}"  # a story's content.prompt_version
    ATTACK_WRITER: Final = f"attack writer-{NUMBER}"  # content.prompt_version of a run with pipeline "attack"
    REMEDIATION: Final = f"remediation-{NUMBER}"  # every remediation plan version
    MITRE_WRITER: Final = f"mitre writer-{MITRE_PROMPTS['version']}"  # a MITRE run card's, app/mitre_prompts.toml


#: Temperature per chat task: 0.0 for a repeatable answer; None = the provider's default. Scenario writing at 0.6:
#: a new action (a new epoch) still gets a new answer, without Kimi-K2.6's stray Chinese words (0 in 192 answers).
CHAT_TEMPERATURES: Final[dict[AiTask, float | None]] = {
    AiTask.SERVICE_MAPPER: 0.0,
    AiTask.RELEVANCE_GATE: 0.0,
    AiTask.GAP_FILL: 0.0,
    AiTask.REMEDIATION_PLAN: 0.0,
    AiTask.LINK_CONTROLS: 0.0,
    AiTask.PICK_CONTROLS: 0.0,
    AiTask.WRITE_SCENARIO: 0.6,
    AiTask.REPAIR_SCENARIO: None,
    AiTask.MITRE_ACTOR_SELECTION: 0.0,
    AiTask.MITRE_PLAN: 0.1,
    AiTask.MITRE_DUPLICATE_CHECK: 0.0,
    AiTask.MITRE_WRITE: 0.1,
}
#: The asks a run answers with an earlier run's answer to the very same conversation, within
#: CII_THREAT_FINDING_REUSE_HOURS: threat finding's and the MITRE actor selection, asked at 0.0 for a repeatable answer.
REUSED_ACROSS_RUNS: Final = frozenset({AiTask.RELEVANCE_GATE, AiTask.GAP_FILL, AiTask.MITRE_ACTOR_SELECTION})

#: Most answer tokens per chat task (CII_ANSWER_TOKENS_<TASK>), counted against the AI service's budget while
#: a question runs; an answer cut off at it is asked again at the model's limit, as a thinking model is (one
#: that ran away, AiLimits.RUNAWAY_*, at the same limit).
CHAT_MAX_OUTPUT_TOKENS: Final[dict[AiTask, int]] = {
    AiTask.RELEVANCE_GATE: TUNING.answer_tokens_relevance_gate,
    AiTask.GAP_FILL: TUNING.answer_tokens_gap_fill,
    AiTask.WRITE_SCENARIO: TUNING.answer_tokens_write_scenario,
    AiTask.REPAIR_SCENARIO: TUNING.answer_tokens_repair_scenario,
    AiTask.REMEDIATION_PLAN: TUNING.answer_tokens_remediation_plan,
    AiTask.SERVICE_MAPPER: TUNING.answer_tokens_service_mapper,
    AiTask.LINK_CONTROLS: TUNING.answer_tokens_link_controls,
    AiTask.PICK_CONTROLS: TUNING.answer_tokens_pick_controls,
    AiTask.MITRE_ACTOR_SELECTION: TUNING.answer_tokens_mitre_actor_selection,
    AiTask.MITRE_PLAN: TUNING.answer_tokens_mitre_plan,
    AiTask.MITRE_DUPLICATE_CHECK: TUNING.answer_tokens_mitre_duplicate_check,
    AiTask.MITRE_WRITE: TUNING.answer_tokens_mitre_write,
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
    # collMod refused while the stored rule requires fields the code no longer writes: every insert fails
    MONGODB_VALIDATOR_STALE = "mongodb.validator_stale"
    # a start-up index build outlasted the socket timeout: the server goes on building it, start-up goes on
    MONGODB_INDEX_STILL_BUILDING = "mongodb.index_still_building"
    AI_CALL = "ai.call"
    AI_CALL_RECORD_FAILED = "ai.call_record_failed"
    AI_CALL_REFUSED = "ai.call_refused"  # a key, permission or model name the gateway refused
    AI_CALL_UNAVAILABLE = "ai.call_unavailable"
    AI_ANSWER_REUSED = "ai.answer_reused"  # this job got this exact conversation's answer before: no call
    AI_ANSWER_LOOKUP_FAILED = "ai.answer_lookup_failed"  # the AI is asked instead
    AI_FIRST_ANSWER_KEPT = "ai.first_answer_kept"  # a re-ask failed: the usable first answer, faults and all
    AI_CUT_OFF_ANSWER_READ = "ai.cut_off_answer_read"  # whole but for its end at the limit: read, not asked again
    AI_GATEWAY_ROUTE = "ai.gateway_route"
    AI_REQUEST_RATE_BUSY = "ai.request_rate_busy"
    AI_SLOTS_BUSY = "ai.slots_busy"
    AI_SLOT_FREE_FAILED = "ai.slot_free_failed"
    # Redis failed: at cap 0 AI calls go ahead uncounted and unlimited, and requests unspaced; at any cap a
    # 429 or an answer could not change the limit
    AI_SLOTS_UNTRACKED = "ai.slots_untracked"
    AI_LIMIT_CUT = "ai.limit_cut"  # a gateway 429 set the limit on AI calls in flight
    LIBRARY_RELOADED = "library.reloaded"
    LIBRARY_CHECK_FAILED = "library.check_failed"
    LIBRARY_INDEXES_BUILT = "library.indexes_built"
    LIBRARY_INDEXES_BUILD_FAILED = "library.indexes_build_failed"
    PLANNER_THREATS_NOT_JUDGED = "planner.threats_not_judged"  # a gate or gap-fill reply skipped
    PLANNER_FUNNEL = "planner.funnel"  # a plan made: how many candidates entered and left each stage
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
    JOB_NOT_CLAIMED = "job.not_claimed"  # a delivery that found its job not queued, due or at its epoch
    CLOCK_OFF = "clock.off"  # this pod's clock differs from MongoDB's by more than Clock.WARN_OVER_SECONDS
    JOB_LEASE_LOST = "job.lease_lost"
    JOB_STOPPED_BY_OWNER = "job.stopped_by_owner"  # its run or plan was cancelled or deleted
    JOB_STOPPED_HANDED_BACK = "job.stopped_handed_back"  # its stopping worker gave it back: not a stall
    JOB_LEASE_RENEW_FAILED = "job.lease_renew_failed"
    JOB_RETRY_SCHEDULED = "job.retry_scheduled"
    JOB_WAITING = "job.waiting"  # given back to look again: another job holds what it needs (not an outage)
    JOB_FAILED = "job.failed"
    JOB_FAILURE_NOT_SAVED = "job.failure_not_saved"  # MongoDB down: the reaper settles the job later
    JOB_UNEXPECTED_ERROR = "job.unexpected_error"  # a bug: logged with its traceback
    JOB_HANDED_BACK = "job.handed_back"  # a stopping worker queued its running job again, no attempt used
    JOB_REQUEUED = "job.requeued"
    JOB_SEND_FAILED = "job.send_failed"
    JOB_QUEUE_SIZE_UNKNOWN = "job.queue_size_unknown"
    JOB_REAP_FAILED = "job.reap_failed"
    WORKER_METRICS_SERVING = "worker.metrics_serving"
    WORKER_HEARTBEAT_FAILED = "worker.heartbeat_failed"
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
    EXTERNAL_INTELLIGENCE_SCHEDULE_SAVED = "external_intelligence.schedule_saved"
    EXTERNAL_INTELLIGENCE_SCHEDULE_CLAIMED = "external_intelligence.schedule_claimed"  # a due import started
    # an import deleted what a source no longer imported left: its records and status document
    EXTERNAL_INTELLIGENCE_REMOVED_SOURCES_DELETED = "external_intelligence.removed_sources_deleted"
    ATTACK_GRAPH_STORED = "attack.graph_stored"  # one source's ATT&CK graph replaced in tsg_attack
    ATTACK_NAME_NOT_CONFIRMED = "attack.name_not_confirmed"  # a group, technique or mitigation ATT&CK lacks
    ATTACK_SCENARIO_NOT_CONFIRMED = "attack.scenario_not_confirmed"  # no confirmed group or technique: given up
    CONTROL_LINKS_PREPARED = "control_links.prepared"  # one linking run: judged, unchanged, failed
    CONTROL_LINKS_BUSY = "control_links.busy"  # another linking run holds the lock
    CONTROL_LINKS_LOCK_LOST = "control_links.lock_lost"  # the lock expired and another run took it
    CONTROL_LINKS_NOT_QUEUED = "control_links.not_queued"  # after an import: the queue was unreachable
    CONTROL_LINKS_EMBED_FAILED = "control_links.embed_failed"  # every mitigation keeps its earlier links
    CONTROL_LINK_FAILED = "control_links.link_failed"  # one mitigation: its earlier links stay
    CONTROLS_PICKED = "controls.picked"  # a written set's controls picked per sentence
    CONTROLS_PICK_DROPPED = "controls.pick_dropped"  # a pick code refused, with its reason
    CONTROLS_PICK_UNUSABLE = "controls.pick_unusable"  # the answer could not be used: the search maps the set
    MITRE_RUN_PLANNED = "mitre.run_planned"  # a MITRE run's actors selected and paths planned and stored
    MITRE_FURTHER_PATHS_PLANNED = "mitre.further_paths_planned"  # an "all paths" run's "any others?" round
    MITRE_SET_WRITTEN = "mitre.set_written"  # one set of a MITRE run: written, dropped, seconds
    MITRE_PATH_DROPPED = "mitre.path_dropped"  # one path's scenario failed its checks or its AI answer
    MITRE_ACTOR_SLICE_FAILED = "mitre.actor_slice_failed"  # one slice of actor profiles got no usable answer
    MITRE_PLANNER_SCOPE_FAILED = "mitre.planner_scope_failed"  # one planner scope got no usable answer
    MITRE_DUPLICATE_CHECK_FAILED = "mitre.duplicate_check_failed"  # no usable verdict: the round's paths kept
    MITRE_STIX_STORED = "mitre.stix_stored"  # one MITRE domain's STIX objects replaced


class AdminJobKind(StrEnum):
    """What an admin job does (tsg_admin_jobs.kind); one of each kind at a time."""

    EMBEDDINGS_BUILD = "embeddings_build"  # the library's vectors made now, not at the next build
    INTEL_REFRESH = "intel_refresh"  # external intelligence sources read now, not at the next check


#: tsg_admin_jobs.kind of a control-links preparation. Not an AdminJobKind member: that enum is part of
#: AdminJobOut, a response shape the UI already reads, and those never change.
CONTROL_LINKS_JOB_KIND: Final = "control_links"


class AdminJobs:
    STALE_AFTER_SECONDS: Final = 3_600  # a job not started this long is abandoned: a new request takes over
    KEEP_DAYS: Final = 90  # tsg_admin_jobs retention (TTL on created_at)


class AdminJobMessage(StrEnum):
    IN_PROGRESS = "An embeddings build is already queued or running: details.job_id names it."
    NOT_FOUND = "Admin job '{job_id}' does not exist."
    NOT_SENT = "The job queue is unreachable: the build was not started. Try again shortly."
    ABANDONED = "Its worker stopped (or it never started in {seconds} s): marked failed; a new one can start."


class Module(StrEnum):
    """The product module a job works for: on every job.started/job.finished log line and every
    GET /v1/admin/jobs row, so a job is traced to its module without knowing task names."""

    THREAT_SCENARIOS = "threat_scenarios"
    REMEDIATION = "remediation"
    SERVICE_MAPPER = "service_mapper"
    EXTERNAL_INTELLIGENCE = "external_intelligence"
    LIBRARY_EMBEDDINGS = "library_embeddings"
    MAINTENANCE = "maintenance"


#: Each task's and each admin job kind's module.
JOB_MODULES: Final[dict[str, Module]] = {
    TaskName.FIND_THREATS: Module.THREAT_SCENARIOS,
    TaskName.WRITE_SCENARIOS: Module.THREAT_SCENARIOS,
    TaskName.WRITE_MITRE_SCENARIOS: Module.THREAT_SCENARIOS,
    TaskName.MAP_CONTROLS: Module.THREAT_SCENARIOS,
    TaskName.RETRY_CONTROLS: Module.THREAT_SCENARIOS,
    TaskName.WRITE_PLAN: Module.REMEDIATION,
    TaskName.MAP_SERVICES: Module.SERVICE_MAPPER,
    TaskName.REFRESH_EXTERNAL_INTELLIGENCE: Module.EXTERNAL_INTELLIGENCE,
    AdminJobKind.INTEL_REFRESH: Module.EXTERNAL_INTELLIGENCE,
    TaskName.LINK_MITIGATIONS: Module.EXTERNAL_INTELLIGENCE,
    CONTROL_LINKS_JOB_KIND: Module.EXTERNAL_INTELLIGENCE,
    TaskName.BUILD_LIBRARY_INDEXES: Module.LIBRARY_EMBEDDINGS,
    AdminJobKind.EMBEDDINGS_BUILD: Module.LIBRARY_EMBEDDINGS,
    TaskName.REAP: Module.MAINTENANCE,
    TaskName.ROLL_UP_AI_USAGE: Module.MAINTENANCE,
}


#: The task that runs each admin job kind: the reaper's job.failed line for an abandoned one names it.
ADMIN_JOB_TASKS: Final[dict[str, str]] = {
    AdminJobKind.EMBEDDINGS_BUILD: TaskName.BUILD_LIBRARY_INDEXES,
    AdminJobKind.INTEL_REFRESH: TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
    CONTROL_LINKS_JOB_KIND: TaskName.LINK_MITIGATIONS,
}


class AbandonReason(StrEnum):
    """Why a job was given up (a job_abandoned error's reason); the job.failed lines carry the same words."""

    WORKER_STOPPED = "abandoned"  # its worker stopped renewing its lease on every attempt
    NEVER_STARTED = "never_started"  # sent again and again, or left queued, and no worker ever took it
    WAITED_TOO_LONG = "waited_too_long"  # it waited Lease.MAX_WAIT_SECONDS for another job to finish


#: The collection whose record carries each task's leased job (a refused send is noted there).
JOB_RECORD_COLLECTIONS: Final[dict[str, Collection]] = {
    TaskName.FIND_THREATS: Collection.SESSIONS,
    TaskName.WRITE_SCENARIOS: Collection.SESSIONS,
    TaskName.WRITE_MITRE_SCENARIOS: Collection.SESSIONS,
    TaskName.WRITE_PLAN: Collection.REMEDIATIONS,
    TaskName.MAP_SERVICES: Collection.SERVICE_MAPPINGS,
}


def module_of(kind: str) -> str:
    """The module of a task or admin job kind; "other" for one not listed."""
    return JOB_MODULES.get(kind, "other")


class JobMonitorMessage(StrEnum):
    NOT_FOUND = "Job '{job_id}' does not exist (or ended more than its listing's retention ago)."
    NOT_ADMIN_JOB = (
        "Job '{job_id}' is a {module} job: cancel it with its own call (a run: POST "
        "/v1/sessions/{{id}}/cancel; a plan: its cancel call). Only intelligence imports and embeddings "
        "builds are cancelled here."
    )
    ALREADY_ENDED = "Job '{job_id}' is already {status}: there is nothing to cancel."


class Timeouts:
    """Every network wait is bounded, so a hung store never holds a worker thread for ever."""

    MONGO_MS: Final = 5_000  # find a server / open a connection
    MONGO_SOCKET_MS: Final = 30_000  # one network wait inside an operation
    MONGO_MAJORITY_WRITE_MS: Final = 10_000  # a write waits this long for a majority to confirm it
    SQL_CONNECT_SECONDS: Final = 5  # short, so an outage answers 503 quickly
    SQL_QUERY_SECONDS: Final = 30  # one procedure call
    REDIS_SECONDS: Final = 5  # connect and each command
    REDIS_HEALTH_CHECK_SECONDS: Final = 30  # a pooled connection idle this long is PINGed before use
    READY_CHECK_SECONDS: Final = 5  # /ready waits at most this for its checks; a slower one counts as down
    READY_CHECK_REUSE_SECONDS: Final = 2  # a finished check is reused this long (below the probe period)
    RECORD_WRITE_SECONDS: Final = 5  # an audit or AI-call record write never holds an answer longer


class Cache:
    SERVICE_MAPPER_CATALOG_SECONDS: Final = 60
    API_KEY_TTL_SECONDS: Final = 60  # an API key is checked again after this
    LIBRARY_STAMP_EVERY_SECONDS: Final = 60  # the library stamp is read again after this
    LIBRARY_INDEXES_EVERY_SECONDS: Final = 1_800  # the maintenance worker embeds new library rows this often
    QUERY_VECTOR_DAYS: Final = 14  # a search query's vector expires after this
    RETIRED_VECTOR_DAYS: Final = 365  # a library vector no row uses is kept this long, then deleted


class Clock:
    CHECK_EVERY_SECONDS: Final = 60  # each process asks MongoDB its time this often (app/core/clock.py)
    WARN_OVER_SECONDS: Final = 5  # a pod clock further off than this is logged (and alerted: ClockSkew)
