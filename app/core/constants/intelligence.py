"""External intelligence feeds: sources, records, snapshots, the refresh and the readers' limits."""

from enum import StrEnum
from typing import Final


class IntelSource(StrEnum):
    """The sources imported."""

    ATTACK_ENTERPRISE = "mitre_attack_enterprise"  # techniques and sub-techniques; for IT assets
    ATTACK_ICS = "mitre_attack_ics"  # techniques and sub-techniques; for OT assets


#: The feeds taken out of the app; an import deletes what they left (named, so no future source is ever deleted).
REMOVED_INTEL_SOURCES: Final = ("cisa_kev", "first_epss", "nist_nvd", "cisa_ics_advisories")


class IntelKind(StrEnum):
    TECHNIQUE = "technique"  # an ATT&CK technique or sub-technique


class IntelState(StrEnum):
    """`tsg_intel.state`: only a valid, current record reaches a snapshot."""

    VALID = "valid"


class FeedStatus(StrEnum):
    """`tsg_external_feed_status.status`: what the last refresh of a source did."""

    NEVER_RUN = "never_run"
    OK = "ok"
    FAILED = "failed"  # the last good data stays in use while it is fresh enough


class SnapshotState(StrEnum):
    """`tsg_external_intelligence_snapshots.state`: one snapshot is active; a newer one replaces it whole."""

    ACTIVE = "active"


class IntelDocId:
    """The fixed `_id` of the one-per-system documents of the intelligence collections."""

    SWITCH: Final = "switch"  # tsg_external_feed_status: the runtime on/off switch
    ACTIVE_SNAPSHOT: Final = "active"  # tsg_external_intelligence_snapshots: the pointer to the active one
    SCHEDULE: Final = "schedule"  # tsg_external_feed_status: when the import runs by itself


class ScheduleFrequency(StrEnum):
    """How often the saved schedule imports."""

    DAILY = "daily"
    WEEKLY = "weekly"  # on day_of_week


class IntelSchedule:
    """The import schedule an admin saves; the defaults serve a database that holds none yet."""

    TIME_PATTERN: Final = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"  # HH:MM, 24-hour; \d would take any script's digits
    RETRY_SECONDS: Final = 3_600  # a scheduled import that failed is due again this soon
    DEFAULT_ENABLED: Final = True
    DEFAULT_FREQUENCY: Final = ScheduleFrequency.WEEKLY
    DEFAULT_DAY_OF_WEEK: Final = 6  # Monday = 0, so Sunday
    DEFAULT_TIME: Final = "02:00"
    DEFAULT_TIMEZONE: Final = "UTC"


class IntelScheduleMessage(StrEnum):
    TIMEZONE_UNKNOWN = "Unknown time zone '{timezone}': give an IANA name such as UTC or Asia/Dubai."
    DAY_REQUIRED = "day_of_week (0 = Monday ... 6 = Sunday) is required when frequency is weekly."


class IntelMessage(StrEnum):
    """Every intelligence exception and refresh failure message."""

    NOT_ANSWERED = "{url} did not answer after {attempts} attempts (last: {reason})."
    REFUSED = "{url} answered with status {status}."
    BAD_FORMAT = "{source} returned data in an unexpected format."
    SNAPSHOT_EMPTY = "No approved intelligence record is current: the snapshot was not built."
    SNAPSHOT_INCONSISTENT = "The snapshot holds {rows} records but {vectors} vectors: it was not used."
    NO_DATA_YET = (
        "External intelligence is on (EXTERNAL_INTELLIGENCE_ENABLED=true) but holds no data yet. Import it: "
        "POST /v1/tsg/intel/refresh, then GET /v1/tsg/intel/health until snapshot_id is set. Or turn it off: "
        'PUT /v1/tsg/intel/switch {"enabled": false}.'
    )
    UNEXPECTED = "The refresh stopped with an unexpected {error}."
    CUT_SHORT = (
        "{source} delivered only {kept} of its {current} current records: the feed looks cut short, so "
        "nothing was stored or retired and the last good data stays."
    )


class IntelRejection(StrEnum):
    """Why a source record was rejected (`RejectedRecord.reason`)."""

    NO_TECHNIQUE_ID = "The technique has no mitre-attack external id."
    NO_NAME = "The technique has no name."
    UNSAFE_TEXT = "The text reads as instructions to an AI system, not as a description."


class IntelRefreshMessage(StrEnum):
    """What an intelligence refresh request answers."""

    IN_PROGRESS = "An intelligence refresh is already queued or running: details.job_id names it."
    NOT_SENT = "The job queue is unreachable: the refresh was not started. Try again shortly."
    SWITCH_OFF = "External intelligence is off: nothing was refreshed."
    SOURCES_FAILED = (
        "These feeds could not be imported and keep their last good data: {sources}. GET /v1/tsg/intel/health says why."
    )


class IntelWorkEvent(StrEnum):
    """Log events of the worker's intelligence code."""

    WARM_UP_FAILED = "external_intelligence.warm_up_failed"
    WARM_UP_SKIPPED = "external_intelligence.warm_up_skipped"
    FOLLOW_FAILED = "external_intelligence.follow_failed"  # asked again next interval
    REFRESH_JOB_FAILED = "external_intelligence.refresh_job_failed"


class IntelLimits:
    FETCH_TIMEOUT_SECONDS: Final = 60
    FETCH_ATTEMPTS: Final = 3
    FAILURE_REASON_CHARS: Final = 200  # how much of a network error's text a failure keeps
    BATCH_SIZE: Final = 1000  # records per bulk write
    CHECK_EVERY_SECONDS: Final = 60  # beat asks whether the saved schedule is due
    CLAIM_STALE_SECONDS: Final = 3_600  # a refresh claim this old belongs to a dead worker: taken over
    SWITCH_CACHE_SECONDS: Final = 60  # how long a process remembers the on/off switch
    INDEX_AT_START_SECONDS: Final = 120  # a scenarios worker's longest wait for its index before it consumes
    MAX_REJECTED_PER_RUN: Final = 100  # rejections kept per run, so one bad file cannot flood a result
    MIN_RETIRE_RATIO: Final = 0.5  # a fetch holding less of the current records is failed, never a mass removal
    RETIRED_VERSION_DAYS: Final = 90  # a version no longer current is deleted this long after it stopped


class SourceDownload:
    """What one download and one parse may cost."""

    MAX_BYTES: Final = 256 * 1024 * 1024  # one HTTP body
    MAX_PARSED_BYTES: Final = 128 * 1024 * 1024  # one JSON text handed to a parser
    CHUNK_BYTES: Final = 1024 * 1024
    MAX_RETRY_AFTER_SECONDS: Final = 60  # the longest "retry-after" a busy server is believed
    MAX_ATTACK_BYTES: Final = 64 * 1024 * 1024
    MAX_REDIRECTS: Final = 3


class AttackReading:
    """How much of one ATT&CK object is kept."""

    FORMAT: Final = "9"  # what the reader keeps of a file: a checkpoint of another format reads it again
    REAL_WORLD_USE_LIMIT: Final = 5
    MITIGATIONS_IN_TEXT: Final = 5
    TEXT_LIMIT: Final = 1500  # characters of the search text the technique's own description may use
    TAIL_ROOM: Final = 250  # tactics, platforms and mitigations follow the description
    LABEL_CHARS: Final = 60
