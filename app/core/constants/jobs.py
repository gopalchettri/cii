"""Background jobs and runs: queues, tasks, events, workers, leases, job control, run states, conflicts."""

from enum import StrEnum
from typing import Final


class Queue(StrEnum):
    THREATS = "tsg_threats"
    SCENARIOS = "tsg_scenarios"
    CONTROLS = "tsg_controls"
    MAINTENANCE = "tsg_maintenance"  # long admin jobs: library builds, intelligence refreshes
    REAPER = "tsg_reaper"  # the reaper and the controls sweep alone: no long job takes their threads
    REMEDIATION = "tsg_remediation"
    SERVICEMAPPER = "tsg_servicemapper"


class TaskName(StrEnum):
    MAP_SERVICES = "tsg_map_services"
    FIND_THREATS = "tsg_find_threats"
    WRITE_SCENARIOS = "tsg_write_scenarios"
    MAP_CONTROLS = "tsg_map_controls"
    REAP = "tsg_reap"
    RETRY_CONTROLS = "tsg_retry_controls"
    BUILD_LIBRARY_INDEXES = "tsg_build_library_indexes"
    WRITE_PLAN = "tsg_write_plan"  # one remediation plan version
    REFRESH_EXTERNAL_INTELLIGENCE = "tsg_refresh_external_intelligence"  # sources due, then a snapshot


TASK_ROUTES: Final[dict[str, dict[str, str]]] = {  # each task's queue (the Celery app's task_routes)
    TaskName.MAP_SERVICES: {"queue": Queue.SERVICEMAPPER},
    TaskName.FIND_THREATS: {"queue": Queue.THREATS},
    TaskName.WRITE_SCENARIOS: {"queue": Queue.SCENARIOS},
    TaskName.MAP_CONTROLS: {"queue": Queue.CONTROLS},
    TaskName.WRITE_PLAN: {"queue": Queue.REMEDIATION},
    TaskName.REAP: {"queue": Queue.REAPER},
    TaskName.RETRY_CONTROLS: {"queue": Queue.REAPER},
    TaskName.BUILD_LIBRARY_INDEXES: {"queue": Queue.MAINTENANCE},
    TaskName.REFRESH_EXTERNAL_INTELLIGENCE: {"queue": Queue.MAINTENANCE},
}
#: The queues some task is routed to: /ready needs a live worker on each (an unrouted queue needs none).
ROUTED_QUEUES: Final[tuple[str, ...]] = tuple(sorted({route["queue"] for route in TASK_ROUTES.values()}))


class AdminJobKind(StrEnum):
    """What an admin job does (tsg_admin_jobs.kind); one of each kind at a time."""

    EMBEDDINGS_BUILD = "embeddings_build"  # the library's vectors made now, not at the next build
    INTEL_REFRESH = "intel_refresh"  # external intelligence sources read now, not at the next check


class AdminJobs:
    STALE_AFTER_SECONDS: Final = 3_600  # a job not started this long is abandoned: a new request takes over
    KEEP_DAYS: Final = 90  # tsg_admin_jobs retention (TTL on created_at)


class AdminJobMessage(StrEnum):
    IN_PROGRESS = "An embeddings build is already queued or running: details.job_id names it."
    NOT_FOUND = "Admin job '{job_id}' does not exist."
    NOT_SENT = "The job queue is unreachable: the build was not started. Try again shortly."
    ABANDONED = "Its worker stopped (or it never started in {seconds} s): marked failed; a new one can start."


class Event(StrEnum):
    """Names of the server-sent events (the `event:` line of each message)."""

    SESSION_UPDATED = "session.updated"
    REMEDIATION_UPDATED = "remediation.updated"
    MAPPING_UPDATED = "mapping.updated"
    SESSION_DELETED = "session.deleted"  # the run is gone: the stream ends
    REMEDIATION_DELETED = "remediation.deleted"  # the plan is gone with its run: the stream ends


class Realtime:
    """Live updates: Server-Sent Events from the API, fed by the workers' Redis pub/sub messages."""

    SESSION_CHANNEL: Final = "tsg:events:session:{session_id}"  # one Redis channel per run
    REMEDIATION_CHANNEL: Final = "tsg:events:remediation:{remediation_id}"  # one per remediation plan
    MAPPING_CHANNEL: Final = "tsg:events:mapping:{mapping_id}"
    CHANNEL_PATTERN: Final = "tsg:events:*"  # one subscription per API process covers every channel
    RETRY_MS: Final = 3_000  # tells a client how soon to reconnect after its stream drops
    STREAM_BUFFER: Final = 16  # updates held for a slow client; the oldest is dropped
    POLL_SECONDS: Final = 5  # the shared subscription checks its connection at least this often
    RECONNECT_SECONDS: Final = 2  # wait before re-subscribing after Redis dropped the connection
    RECHECK_SECONDS: Final = 30  # an unfinished run's stream reads its status again this often
    SILENT_LIMIT_SECONDS: Final = 15  # no message and no PONG this long: the connection counts as lost
    COALESCE_SECONDS: Final = 0.25  # a stream waits this long after a change, so a burst costs one read


class Worker:
    THREADS: Final = 4  # tasks at once when a worker's command names none: each Deployment's -c sets its own
    BROKER_KEY_PREFIX: Final = "tsg:"  # every Celery key in Redis: v1 must not share the Redis database
    BROKER_VISIBILITY_SECONDS: Final = 4_200  # > Lease.MAX_JOB_SECONDS + Lease.SECONDS: never redelivered
    HEARTBEAT_SECONDS: Final = 20  # each worker pod tells /ready "alive" this often
    ONLINE_WITHIN_SECONDS: Final = 60  # /ready counts a worker only if its last beat is this recent
    HEARTBEAT_KEY: Final = "tsg:workers:{queue}"  # sorted set: member = worker hostname, score = last beat
    #: Touched by the worker's heartbeat thread each beat, whatever Redis says; the pod's liveness probe reads
    #: its age, so a broker outage never restarts a healthy worker (and kills its running jobs).
    LIVENESS_FILE: Final = "/tmp/tsg-worker-alive"  # noqa: S108 — a per-pod marker, no data
    LIVENESS_MAX_AGE_SECONDS: Final = 180  # the probe fails when the file is older: hung or dead
    NEXT_STAGE_PRIORITY: Final = 0  # next stages, retries, the reaper's re-sends: Redis serves 0 first
    NEW_WORK_PRIORITY: Final = 3  # every other send; its list is <queue>\x06\x163, which old pods read too


class Lease:
    SECONDS: Final = 120  # a lease not renewed for this long is taken back by the reaper
    RENEW_EVERY_SECONDS: Final = 30
    REAPER_EVERY_SECONDS: Final = 60  # the reaper repairs abandoned and lost jobs this often
    MAX_ATTEMPTS: Final = 5  # then the record is failed with job.error
    REQUEUE_QUEUED_AFTER_SECONDS: Final = 120
    RESEND_ANYWAY_AFTER_SECONDS: Final = 900  # a job queued this long is sent again even behind a backlog
    MAX_JOB_SECONDS: Final = 3_600  # a job running this long stops renewing, so a hung job is taken over
    RETRY_DELAYS_SECONDS: Final = (15, 30, 60, 120)  # wait before retrying after an outage, by attempt
    CLOCK_SKEW_SECONDS: Final = 5  # a claim accepts a job due this much later than the pod's clock
    RESEND_EARLY_WITHIN_SECONDS: Final = RETRY_DELAYS_SECONDS[-1] + CLOCK_SKEW_SECONDS  # retry early: re-sent


class JobKind(StrEnum):
    """What a job in the jobs list does."""

    THREATS = "threats"  # finding a run's threats and freezing its plan
    SCENARIOS = "scenarios"  # writing a run's scenarios (a set, or a regenerate)
    CONTROLS = "controls"  # matching controls to a run's written scenarios
    REMEDIATION = "remediation"  # writing one version of a remediation plan
    SERVICE_MAPPING = "service_mapping"  # generating one version of a service mapping


class JobControl:
    LIST_MAX: Final = 200  # the jobs list's length, oldest first


class JobControlMessage(StrEnum):
    NOTHING_TO_CANCEL = "Session '{session_id}' has no job queued or running and no controls being matched."
    PLAN_NOTHING_TO_CANCEL = "Remediation plan '{remediation_id}' is not being written."
    BEING_DELETED = (
        "Session '{session_id}' is being deleted: nothing more can start on it (if a delete was cut short, "
        "delete it again to finish)."
    )
    CANCEL_FIRST = (
        "Session '{session_id}' still has work queued or running (a job, controls or a remediation plan): "
        "cancel it first, then delete."
    )


class Generation:
    WRITER_BATCH: Final = 6  # paths one write job writes at once (a set in one round): not a scenario limit
    MAX_PATH_ATTEMPTS: Final = 5  # failed or blocked this often, a path is abandoned and never served
    MAX_SUPPORTING_SYSTEMS: Final = 0  # supporting systems a run takes; 0 = unlimited


class SessionMessage(StrEnum):
    NOT_FOUND = "Session '{session_id}' does not exist."
    OTHER_ENTITY = "Session '{session_id}' belongs to another entity."
    ASSET_NOT_OWNED = "Asset {asset_id} does not belong to your entity."
    SYSTEMS_NOT_LINKED = "Supporting systems {system_ids} are not linked to asset {asset_id}."
    SERVICE_NOT_FOUND = "Service {service_id} does not exist."
    SECTOR_NOT_FOUND = "Sector {sector_id} does not exist."
    SECTOR_NOT_PARENT = (
        "Sector {sector_id} is not the parent of sub-sector {subsector_id}; its sector is {parent_id}."
    )
    IDEMPOTENCY_KEY_CONFLICT = "This Idempotency-Key was already used for another request."
    ENTITY_MISMATCH = "The entity in the path is not the caller's entity."
    ENTITY_MISMATCH_BODY = "manual_scenario.entity_id is not the caller's entity (X-Entity-Id)."
    SCENARIO_NOT_FOUND = "Scenario '{scenario_id}' does not exist in session '{session_id}'."
    SYSTEMS_REQUIRED = "Send at least one supporting system."
    SYSTEMS_REPEATED = "Each supporting system may be sent only once."
    TOO_MANY_SYSTEMS = "A run takes at most {limit} supporting systems."
    IDEMPOTENCY_KEY_RUN_GONE = (
        "The run that took this Idempotency-Key was deleted while this request started; send it again."
    )


class GroundingStatus(StrEnum):
    """A scenario's threat.grounding_status in the results."""

    VERIFIED = "verified"  # a library threat
    UNVERIFIED = "unverified"  # the AI's gap-fill threat, or one a person named that no curator approved yet


class ValidationStatus(StrEnum):
    """Scenario.validation.status, computed on read."""

    OK = "ok"
    WARNING = "warning"


class RunKind(StrEnum):
    GENERATED = "generated"  # threats, paths and scenarios made by the engine
    MANUAL = "manual"  # one hand-written scenario (a remediation request): born done


class RunActionKind(StrEnum):
    """last_action.kind: what the reviewer last asked of the run."""

    START = "start"
    NEXT_SET = "next_set"
    REGENERATE = "regenerate"


class RunActionOutcome(StrEnum):
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"  # done, but a path was abandoned or a regenerate kept an old version
    FAILED = "failed"  # the job failed (its error is job.error)
    CANCELLED = "cancelled"


class StageState(StrEnum):
    """One stage of a run (threats, scenarios, controls) as the status shows it."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"


class RunOverall(StrEnum):
    """What the reviewer should do now (the status's progress.overall)."""

    PENDING = "pending"  # nothing started yet
    IN_PROGRESS = "in_progress"  # wait: work is going on
    AWAITING_REVIEW = "awaiting_review"  # scenarios wait for a decision, AI outage cards for a regenerate
    AWAITING_NEXT_SET = "awaiting_next_set"  # all written ones decided; paths remain: ask for the next set
    COMPLETE = "complete"  # everything written and decided
    ERROR = "error"  # the run failed (once no control is still matched): progress.error_message says why
    CANCELLED = "cancelled"  # its owner stopped it (or a done run's controls): what was done stays readable


class SessionState(StrEnum):
    """The run as a whole (the status's session_status)."""

    ACTIVE = "active"  # a job is queued or running
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BoardMessage(StrEnum):
    """progress.error_message texts the status writes itself (a failed job brings its own message)."""

    ABANDONED = "{abandoned} attack path(s) could not be written."
    CONTROLS_FAILED = (
        "Controls could not be matched for {failed} scenario(s); request or regenerate a plan to try again."
    )
    CONTROLS_FAILED_MANUAL = (
        "Controls could not be matched for the hand-written scenario; regenerate its plan "
        "(POST .../treatment-plan/regenerate) to try again."
    )
    CANCELLED = "Cancelled by user {user} at {at} UTC."
    CONTROLS_CANCELLED = "Matching controls was cancelled for {cancelled} scenario(s)."


class ConflictReason(StrEnum):
    """The `reason` of a 409 (and of a few 403/404/422 answers); the API never changes one."""

    IDEMPOTENCY_KEY_CONFLICT = "idempotency_key_conflict"
    GENERATION_IN_PROGRESS = "generation_in_progress"
    RUN_FAILED = "run_failed"
    RUN_CANCELLED = "run_cancelled"  # cancelled before its plan: nothing to decide or resume
    SCENARIOS_NOT_DECIDABLE = "scenarios_not_decidable"  # per-id reasons are TargetProblem
    SCENARIOS_NOT_REGENERABLE = "scenarios_not_regenerable"
    NOTHING_TO_ACCEPT = "nothing_to_accept"
    DUPLICATE_VERSION = "duplicate_version"
    NOTHING_LEFT = "nothing_left"
    TARGET_REACHED = "target_reached"
    SCENARIOS_ABANDONED = "scenarios_abandoned"
    SCENARIO_NOT_ACCEPTED = "scenario_not_accepted"
    NOTHING_TO_PROMOTE = "nothing_to_promote"
    TYPE_MISMATCH = "type_mismatch"  # a 422: the threat the library holds is of another type
    VERSION_NOT_FOUND = "version_not_found"  # a 404: the plan has no such version
    NOT_COMPLETE = "not_complete"  # a plan version still being written, or failed, cannot be decided
    CHANGED_CONCURRENTLY = "changed_concurrently"
    PLAN_ALREADY_EXISTS = "plan_already_exists"  # one plan per scenario: regenerate it instead
    ASSET_NOT_OWNED = "asset_not_owned"  # a 403
    SYSTEM_NOT_LINKED = "system_not_linked"  # a 403
    REQUIRED_FACTS_MISSING = "required_facts_missing"  # a 422: a required property is not recorded
    JOB_IN_PROGRESS = "job_in_progress"  # an admin job of this kind is queued or running
    NOTHING_TO_CANCEL = "nothing_to_cancel"
    CANCEL_FIRST = "cancel_first"  # a delete refused while a job of it is queued or running
    RUN_BEING_DELETED = "run_being_deleted"
    VERSION_LIMIT_REACHED = "version_limit_reached"  # REGENERATIONS_MAX_VERSION_COUNT reached
    OPERATION_IN_PROGRESS = "operation_in_progress"  # the same SQL Server write is running now
    INTEL_NO_DATA = "intel_no_data"  # a run refused: external intelligence is on but nothing is imported yet


class RunClash(StrEnum):
    """Why a run could not be inserted or queued again (tsg_sessions)."""

    IDEMPOTENCY_KEY = "idempotency_key"  # one run per Idempotency-Key per entity
    CHANGED = "changed"  # the run moved on since it was read: its job was not replaced
    DELETING = "deleting"  # its owner is deleting it: nothing more starts on it


class UnselectedReason(StrEnum):
    """Why a valid attack path gets no scenario (stored on the path in the plan)."""

    TARGET_REACHED = "target_reached"  # TOTAL_SCENARIO_COUNT kept more relevant paths
    REPLACED_AFTER_FAILURE = "replaced_after_failure"  # it failed for good and a reserve path took its place
