"""External intelligence feeds: sources, records, snapshots, the refresh and the readers' limits."""

from enum import StrEnum
from typing import Final


class IntelSource(StrEnum):
    """The approved source set."""

    CISA_KEV = "cisa_kev" # Kind of record:: vulnerability (exploited in real attacks). For::	IT assets
    FIRST_EPSS = "first_epss" # Kindof record:: exploit score, joined to a KEV CVE. For::	IT assets
    ATTACK_ENTERPRISE = "mitre_attack_enterprise"  # Kind of record:: technique or sub-technique. For::	IT assets
    ATTACK_ICS = "mitre_attack_ics"  # Kind of record:: technique or sub-technique. For::	OT assets
    CISA_ICS = "cisa_ics_advisories"  #  Kind of record:: advisory (product, affected versions, fixes, mitigations). For::	OT assets
    NIST_NVD = "nist_nvd"  # Kind of record::CVE detail: CPE applicability, version ranges, CVSS, CWE


class IntelKind(StrEnum):
    TECHNIQUE = "technique"  # an ATT&CK technique or sub-technique
    VULNERABILITY = "vulnerability"  # a KEV entry
    EXPLOIT_SCORE = "exploit_score"  # an EPSS score, joined to a vulnerability by CVE id
    ADVISORY = "advisory"  # an ICS advisory: product, affected versions, fixes, mitigations (OT)
    VULNERABILITY_DETAIL = "vulnerability_detail"  # NVD detail, joined to a vulnerability by CVE id


class IntelState(StrEnum):
    """`tsg_intel.state`: only a valid, current record reaches a snapshot."""

    VALID = "valid"
    QUARANTINED = "quarantined"  # malformed in the source: kept with its reason, never indexed


class FeedStatus(StrEnum):
    """`tsg_external_feed_status.status`: what the last refresh of a source did."""

    NEVER_RUN = "never_run"
    OK = "ok"
    FAILED = "failed"  # the last good data stays in use while it is fresh enough


class SnapshotState(StrEnum):
    """`tsg_external_intelligence_snapshots.state`: one snapshot is active; a newer one replaces it whole."""

    BUILDING = "building"
    ACTIVE = "active"
    SUPERSEDED = "superseded"


class IntelDocId:
    """The fixed `_id` of the one-per-system documents of the intelligence collections."""

    SWITCH: Final = "switch"  # tsg_external_feed_status: the runtime on/off switch
    ACTIVE_SNAPSHOT: Final = "active"  # tsg_external_intelligence_snapshots: the pointer to the active one


class IntelMessage(StrEnum):
    """Every intelligence exception message."""

    NOT_ANSWERED = "{url} did not answer after {attempts} attempts (last: {reason})."
    REFUSED = "{url} answered with status {status}."
    BAD_FORMAT = "{source} returned data in an unexpected format."
    ICS_UNREACHABLE = "{url} failed {count} times in a row: the run was stopped."
    SNAPSHOT_EMPTY = "No approved intelligence record is current: the snapshot was not built."
    SNAPSHOT_INCONSISTENT = "The snapshot holds {rows} records but {vectors} vectors: it was not used."
    NO_DATA_YET = (
        "External intelligence is on (EXTERNAL_INTELLIGENCE_ENABLED=true) but holds no data yet. Import it: "
        "POST /v1/tsg/intel/refresh, then GET /v1/tsg/intel/health until snapshot_id is set. Or turn it off: "
        'PUT /v1/tsg/intel/switch {"enabled": false}.'
    )


class IntelRejection(StrEnum):
    """Why a source record was quarantined (`RejectedRecord.reason`)."""

    NO_TECHNIQUE_ID = "The technique has no mitre-attack external id."
    NO_NAME = "The technique has no name."
    NOT_AN_OBJECT = "The record is not a JSON object."
    KEV_MISSING_FIELD = "The KEV record has no cveID or dateAdded."
    EPSS_BAD_ROW = "The EPSS row has no CVE id or the wrong number of columns."
    EPSS_BAD_SCORE = "The EPSS score or percentile is not a number between 0 and 1."
    ICS_BAD_ADVISORY = "The ICS advisory is not CSAF JSON or has no id, title or release date."
    ICS_DOWNLOAD_FAILED = "The ICS advisory file could not be downloaded."
    NVD_BAD_ITEM = "The NVD item has no valid CVE id or last-modified time."
    UNSAFE_TEXT = "The text reads as instructions to an AI system, not as a description."


class IntelRefreshMessage(StrEnum):
    """What an intelligence refresh request answers."""

    IN_PROGRESS = "An intelligence refresh is already queued or running: details.job_id names it."
    NOT_SENT = "The job queue is unreachable: the refresh was not started. Try again shortly."
    SOURCE_NOT_APPROVED = "The source '{source}' is not approved; approve it before refreshing it."
    SWITCH_OFF = "External intelligence is off: nothing was refreshed."


class IntelWorkEvent(StrEnum):
    """Log events of the worker's intelligence code."""

    WARM_UP_FAILED = "external_intelligence.warm_up_failed"
    WARM_UP_SKIPPED = "external_intelligence.warm_up_skipped"
    FOLLOW_FAILED = "external_intelligence.follow_failed"  # asked again next interval
    REFRESH_SKIPPED = "external_intelligence.refresh_skipped"
    REFRESH_JOB_FAILED = "external_intelligence.refresh_job_failed"


class IntelUrl:
    """Where each source is read from (the sources' own published locations)."""

    CISA_KEV: Final = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    FIRST_EPSS: Final = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    ATTACK_ENTERPRISE: Final = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    ATTACK_ICS: Final = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
    )
    NVD_API: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0" 
    ICS_CSAF: Final = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
    ICS_CHANGES: Final = ICS_CSAF + "changes.csv"  # "<year>/<file>.json","<change time>", newest first
    TERMS_NVD: Final = "https://nvd.nist.gov/developers/terms-of-use"
    TERMS_CISA: Final = "https://www.cisa.gov/news-events/cybersecurity-advisories"
    TERMS_KEV: Final = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    TERMS_EPSS: Final = "https://www.first.org/epss/"
    TERMS_ATTACK: Final = "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"


#: Hours between fetches of a source (ATT&CK is a large file that changes with a release).
REFRESH_AFTER_HOURS: Final[dict[IntelSource, int]] = {
    IntelSource.CISA_KEV: 24,
    IntelSource.FIRST_EPSS: 24,
    IntelSource.ATTACK_ENTERPRISE: 168,
    IntelSource.ATTACK_ICS: 168,
    IntelSource.CISA_ICS: 24,
    IntelSource.NIST_NVD: 24,
}


class IntelLimits:
    PARSER_VERSION: Final = "1"  # bumped when a parser's output changes, so records are re-versioned
    FETCH_TIMEOUT_SECONDS: Final = 60
    FETCH_ATTEMPTS: Final = 3
    FAILURE_REASON_CHARS: Final = 200  # how much of a network error's text a failure keeps
    BATCH_SIZE: Final = 1000  # records per bulk write
    CHECK_EVERY_SECONDS: Final = 3_600  # beat asks which sources are due
    STALE_AFTER_HOURS: Final = 48  # a source not refreshed this long marks its snapshot stale (still used)
    CLAIM_STALE_SECONDS: Final = 3_600  # a refresh claim this old belongs to a dead worker: taken over
    SWITCH_CACHE_SECONDS: Final = 60  # how long a process remembers the on/off switch
    MAX_REJECTED_PER_RUN: Final = 100  # quarantined rows kept per run, so one bad file cannot flood storage
    ICS_FIRST_RUN_MONTHS: Final = 24  # a first CISA ICS run reads only advisories changed this recently
    ICS_MAX_PER_RUN: Final = 400  # advisory files downloaded per run; the next run continues from there
    ICS_MAX_CONSECUTIVE_FAILURES: Final = 5  # advisory files failing in a row mean the host is down
    NVD_SLEEP_UNKEYED_SECONDS: Final = 6.5  # NVD allows 5 requests per 30 s without a key ...
    NVD_SLEEP_KEYED_SECONDS: Final = 0.7  # ... and 50 with one
    NVD_BACKOFF_SECONDS: Final = 35  # after 403/429/503: longer than NVD's 30 s window
    NVD_MAX_REQUESTS_PER_RUN: Final = 150
    NVD_MAX_WINDOW_DAYS: Final = 120  # NVD refuses a lastMod window longer than this
    NVD_PAGE_SIZE: Final = 2_000  # NVD's own maximum resultsPerPage
    NVD_SUMMARY_MAX_CHARS: Final = 600
    NVD_MAX_PATCH_URLS: Final = 3


class IntelOperationsLimits:
    MIN_RETIRE_RATIO: Final = (
        0.5  # a fetch holding less of the current records is failed, never a mass removal
    )
    RETIRED_VERSION_DAYS: Final = 90  # a version no longer current is deleted this long after it stopped


class SourceDownload:
    """What one download and one parse may cost."""

    MAX_BYTES: Final = 256 * 1024 * 1024  # one HTTP body
    MAX_PARSED_BYTES: Final = (
        128 * 1024 * 1024
    )  # one JSON or CSV text handed to a parser, or a gunzipped stream
    CHUNK_BYTES: Final = 1024 * 1024
    MAX_RETRY_AFTER_SECONDS: Final = 60  # the longest "retry-after" a busy server is believed
    MAX_KEV_BYTES: Final = 64 * 1024 * 1024
    MAX_ATTACK_BYTES: Final = 64 * 1024 * 1024
    MAX_ICS_FILE_BYTES: Final = 2 * 1024 * 1024  # one advisory
    MAX_ICS_CHANGES_BYTES: Final = 1024 * 1024  # changes.csv
    MAX_NVD_PAGE_BYTES: Final = 50 * 1024 * 1024
    MAX_REDIRECTS: Final = 3


class SourceHosts:
    """Where a source's links and redirects may lead; a host matches itself and its subdomains."""

    REDIRECTS: Final = ("raw.githubusercontent.com", "cisa.gov", "www.cisa.gov", "epss.empiricalsecurity.com")
    CISA_PAGES: Final = ("cisa.gov",)
    ATTACK_PAGES: Final = ("attack.mitre.org",)
    CISA_ADVISORY_PAGE: Final = "https://www.cisa.gov/news-events/ics-advisories/{advisory_id}"
    ATTACK_TECHNIQUE_PAGE: Final = "https://attack.mitre.org/techniques/{path}"


class KevReading:
    """Characters kept of one CISA KEV entry."""

    VENDOR_PRODUCT_CHARS: Final = 100
    DESCRIPTION_CHARS: Final = 700
    ACTION_CHARS: Final = 300


class EpssReading:
    MAX_ROWS: Final = 2_000_000  # a stream of more is not this file
    FIRST_LINE_BYTES: Final = 1024  # the "#model_version:...,score_date:..." line is far shorter
    MARKER_HEX_CHARS: Final = 12  # characters of the wanted-CVE hash kept in the checkpoint marker


class AttackReading:
    """How much of one ATT&CK object is kept."""

    FORMAT: Final = "8"  # what the reader keeps of a file: a checkpoint of another format reads it again
    REAL_WORLD_USE_LIMIT: Final = 5
    MITIGATIONS_IN_TEXT: Final = 5
    TEXT_LIMIT: Final = 1500  # characters of the search text the technique's own description may use
    TAIL_ROOM: Final = 250  # tactics, platforms and mitigations follow the description
    LABEL_CHARS: Final = 60


class IcsReading:
    """How much of one CISA ICS advisory is kept, and how often a failing file is retried."""

    SUMMARY_CHARS: Final = 450
    MITIGATION_CHARS: Final = 300
    NAME_CHARS: Final = 100
    MAX_PRODUCTS: Final = 5_000
    MAX_MITIGATIONS: Final = 5
    MAX_FAILED_RUNS: Final = 3  # runs a file may fail in before it is rejected instead of retried
    MAX_FAILED_FILES: Final = 50  # failed files remembered in the checkpoint


class SwitchTiming:
    RETRY_AFTER_OUTAGE_SECONDS: Final = 5.0  # with no value yet, the store is asked again this soon


class StoreLimits:
    MAX_ERROR_CHARS: Final = 500  # a stored refresh error
    ACTIVATION_TRIES: Final = 2  # a first activation racing another one can lose its insert once
