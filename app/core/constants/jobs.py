"""Background jobs: queues, tasks, live events, workers and leases."""

from enum import StrEnum
from typing import Final


class Queue(StrEnum):
    THREATS = "tsg_threats"
    SCENARIOS = "tsg_scenarios"
    MAINTENANCE = "tsg_maintenance"


class TaskName(StrEnum):
    FIND_THREATS = "tsg_find_threats"
    WRITE_SCENARIOS = "tsg_write_scenarios"
    MAP_CONTROLS = "tsg_map_controls"
    REAP = "tsg_reap"
    RETRY_CONTROLS = "tsg_retry_controls"
    BUILD_LIBRARY_INDEXES = "tsg_build_library_indexes"
    WRITE_PLAN = "tsg_write_plan"  # one remediation plan version (Step 16)
    REFRESH_EXTERNAL_INTELLIGENCE = "tsg_refresh_external_intelligence"  # sources due, then a snapshot


class AdminJobKind(StrEnum):
    """What an admin job does (tsg_admin_jobs.kind); one of each kind at a time."""

    EMBEDDINGS_BUILD = (
        "embeddings_build"  # #18: the library's vectors made now, not at the next 30-minute build
    )
    INTEL_REFRESH = "intel_refresh"  # external intelligence sources read now, not at the next check


class AdminJobs:
    # A job still queued or running this long counts as abandoned (its worker died, its message was lost): the
    # next request takes over instead of being refused for ever. A full build takes minutes.
    STALE_AFTER_SECONDS: Final = 3_600
    KEEP_DAYS: Final = 90  # tsg_admin_jobs retention (TTL on created_at)


class AdminJobMessage(StrEnum):
    IN_PROGRESS = "An embeddings build is already queued or running: details.job_id names it."
    NOT_FOUND = "Admin job '{job_id}' does not exist."
    NOT_SENT = "The job queue is unreachable: the build was not started. Try again shortly."
    ABANDONED = "Still unfinished after {seconds} s: taken over by a new build."


class Event(StrEnum):
    """Names of the server-sent events (the `event:` line of each message)."""

    SESSION_UPDATED = "session.updated"
    REMEDIATION_UPDATED = "remediation.updated"
    SESSION_DELETED = "session.deleted"  # the run is gone (its owner deleted it, G214): the stream ends
    REMEDIATION_DELETED = "remediation.deleted"  # the plan is gone with its run: the stream ends


class Realtime:
    """Live updates: Server-Sent Events from the API, fed by Redis pub/sub messages the workers publish."""

    SESSION_CHANNEL: Final = "tsg:events:session:{session_id}"  # one Redis channel per run
    REMEDIATION_CHANNEL: Final = "tsg:events:remediation:{remediation_id}"  # one per remediation plan
    CHANNEL_PATTERN: Final = "tsg:events:*"  # one subscription per API process covers every channel
    RETRY_MS: Final = 3_000  # tells a client how soon to reconnect after its stream drops
    STREAM_BUFFER: Final = (
        16  # updates held for a slow client; each is a full status, so the oldest is dropped
    )
    POLL_SECONDS: Final = 5  # the shared subscription checks its connection at least this often
    RECONNECT_SECONDS: Final = 2  # wait before re-subscribing after Redis dropped the connection
    # A stream of an unfinished run reads its status again this often without a message, so a lost last
    # update shows within this time; one small MongoDB read per open stream, none once the run is finished.
    RECHECK_SECONDS: Final = 30
    SILENT_LIMIT_SECONDS: Final = 15  # no message and no PONG this long: the connection counts as lost


class Worker:
    THREADS: Final = 10  # tasks run at once per worker pod; each mostly waits on an AI answer
    # Every Celery key in Redis starts with this (owner 2026-10-08: "tsg:"). v1 uses "tsg:" keys too, so v1
    # and v2 must never run on the same Redis database at the same time. UAT: v1 is being removed, and v2
    # takes databases 0 and 1 once v1 is stopped (owner 2026-10-08). The laptop shares databases 0 and 1 with
    # v1 too (owner 2026-10-09), so run.ps1 refuses to start v2 while v1's worker or beat runs.
    BROKER_KEY_PREFIX: Final = "tsg:"
    # An unacknowledged message is handed to another worker after this; the lease makes a duplicate harmless.
    BROKER_VISIBILITY_SECONDS: Final = 3_600
    HEARTBEAT_SECONDS: Final = 20  # each worker pod tells /ready "alive" this often
    ONLINE_WITHIN_SECONDS: Final = 60  # /ready counts a worker only if its last beat is this recent (3 beats)
    # Redis sorted set per queue: member = worker hostname, score = time of its last beat.
    HEARTBEAT_KEY: Final = "tsg:workers:{queue}"


class Lease:
    SECONDS: Final = 120  # a lease on a job record; one not renewed for this long is taken back by the reaper
    RENEW_EVERY_SECONDS: Final = 30  # the owner renews its lease this often while the job runs
    REAPER_EVERY_SECONDS: Final = 60  # the reaper repairs abandoned and lost jobs this often
    # Attempts at one job; after the last, the record is failed with job.error (it is its own dead letter).
    MAX_ATTEMPTS: Final = 5
    REQUEUE_QUEUED_AFTER_SECONDS: Final = 120
    # A job still queued this long is sent again even when its queue holds other messages: a steady backlog
    # must not hide a lost job for hours (the claim makes a duplicate delivery harmless).
    RESEND_ANYWAY_AFTER_SECONDS: Final = 900
    # A job that runs this long stops renewing its lease, so the reaper takes it over and MAX_ATTEMPTS
    # applies: a hung job (a deadlock, an endless loop) must not hold its run for ever. v1's hard time limit.
    MAX_JOB_SECONDS: Final = 3_600
    # Wait before retrying after a store or AI outage, by attempt (1st, 2nd …); MAX_ATTEMPTS ends it.
    RETRY_DELAYS_SECONDS: Final = (15, 30, 60, 120)
    # A claim accepts a job due up to this much later than the claiming pod's clock: pods' clocks differ a
    # little, and a hand-over must not wait for the reaper. Far below the shortest back-off (15 s).
    CLOCK_SKEW_SECONDS: Final = 5
