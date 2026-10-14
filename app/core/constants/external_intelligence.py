"""External intelligence: its sources, record kinds, states, addresses and limits. Feed addresses and limits
live here, not in settings: they change with a release of the source or of the app, not with an environment.
The words the evidence is said in are in external_intelligence_text.py."""

from enum import StrEnum
from typing import Final


class IntelSource(StrEnum):
    """The approved source set. Other feeds stay out until Legal approves them."""

    CISA_KEV = "cisa_kev"
    FIRST_EPSS = "first_epss"
    ATTACK_ENTERPRISE = "mitre_attack_enterprise"  # IT
    ATTACK_ICS = "mitre_attack_ics"  # OT
    CISA_ICS = "cisa_ics_advisories"  # OT: CSAF advisories with affected products and versions
    NIST_NVD = "nist_nvd"  # CVE detail: CPE applicability, version ranges, CVSS, CWE


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
    FAILED = "failed"  # the last refresh failed; the last good data stays in use while it is fresh enough


class SnapshotState(StrEnum):
    """`tsg_external_intelligence_snapshots.state`: one snapshot is active; a newer one replaces it whole."""

    BUILDING = "building"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    FAILED = "failed"


class Applicability(StrEnum):
    """Whether a vulnerability applies to the asset. Unknown stays unknown: a CVE in KEV or NVD is never
    "exploitable here" on that alone."""

    CONFIRMED = "confirmed"  # the asset's vendor, product and version match the record
    UNKNOWN = "unknown"  # the asset's product or version is not recorded, or the record names none
    NOT_APPLICABLE = "not_applicable"  # the asset's vendor or product differs


class EvidenceRole(StrEnum):
    """What an evidence entry proves (G229, owner 2026-10-13: "Distinguish direct evidence from contextual
    intelligence"): only a weakness confirmed in the asset's own recorded product is direct; a technique, or a
    weakness not known to apply, is context, never proof that this asset is attacked or vulnerable."""

    DIRECT = "direct"
    CONTEXT = "context"


class EvidenceDecision(StrEnum):
    """What became of a candidate in one threat's evidence search (`Considered.decision`)."""

    USED = "used"
    BELOW_THRESHOLD = "below_threshold"  # the reranker scored it under the threshold
    NOT_APPLICABLE = "not_applicable"  # excluded by the applicability check
    NO_PRODUCT_LINK = "no_product_link"  # a product-specific record the asset's recorded products cannot tie
    DUPLICATE = "duplicate"  # the same record already used for this threat
    OVER_LIMIT = "over_limit"  # more relevant records already fill the limit


class EvidenceSearchFailure(StrEnum):
    """Why a threat's evidence search gave nothing for a reason other than "nothing fits"."""

    UNAVAILABLE = "evidence_search_unavailable"  # the embedding or rerank service did not answer
    NO_SNAPSHOT = "no_intelligence_snapshot"  # nothing searched: no snapshot built yet (G229's gate says so)


class IntelMessage(StrEnum):
    """Every intelligence exception message, filled with `.format(...)` by the exception that carries it."""

    NOT_ANSWERED = "{url} did not answer after {attempts} attempts."
    REFUSED = "{url} answered with status {status}."
    BAD_FORMAT = "{source} returned data in an unexpected format."
    ICS_UNREACHABLE = "{url} failed {count} times in a row: the run was stopped."
    SNAPSHOT_EMPTY = "No approved intelligence record is current: the snapshot was not built."
    SNAPSHOT_INCONSISTENT = "The snapshot holds {rows} records but {vectors} vectors: it was not used."


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


class IntelLimits:
    PARSER_VERSION: Final = "1"  # bumped when a parser's output changes, so records are re-versioned
    FETCH_TIMEOUT_SECONDS: Final = 60
    FETCH_ATTEMPTS: Final = 3
    BATCH_SIZE: Final = 1000  # records per bulk write
    CHECK_EVERY_SECONDS: Final = 3_600  # beat asks which sources are due; most hours none is
    STALE_AFTER_HOURS: Final = 48  # a source not refreshed this long marks its snapshot stale (still used)
    CLAIM_STALE_SECONDS: Final = 3_600  # a refresh claim this old belongs to a dead worker: taken over
    SWITCH_CACHE_SECONDS: Final = 60  # how long a process remembers the on/off switch
    MAX_REJECTED_PER_RUN: Final = 100  # quarantined rows kept per run, so one bad file cannot flood storage
    ICS_FIRST_RUN_MONTHS: Final = 24  # a first CISA ICS run reads only advisories changed this recently
    ICS_MAX_PER_RUN: Final = 400  # advisory files downloaded per run; the next run continues from there
    ICS_MAX_CONSECUTIVE_FAILURES: Final = 5  # advisory files failing in a row mean the host is down
    # NVD allows 5 requests per 30 s without a key and 50 with one; the sleeps keep a little under that.
    NVD_SLEEP_UNKEYED_SECONDS: Final = 6.5
    NVD_SLEEP_KEYED_SECONDS: Final = 0.7
    NVD_BACKOFF_SECONDS: Final = 35  # after 403/429/503: longer than NVD's 30 s window
    NVD_MAX_REQUESTS_PER_RUN: Final = 150  # a run is bounded: about 16 minutes without a key
    NVD_MAX_WINDOW_DAYS: Final = 120  # NVD refuses a lastMod window longer than this
    NVD_PAGE_SIZE: Final = 2_000  # NVD's own maximum resultsPerPage
    NVD_SUMMARY_MAX_CHARS: Final = 600
    NVD_MAX_PATCH_URLS: Final = 3


#: Hours between fetches of a source. ATT&CK is a ~40 MB file that changes with a release, so it is weekly.
REFRESH_AFTER_HOURS: Final[dict[IntelSource, int]] = {
    IntelSource.CISA_KEV: 24,
    IntelSource.FIRST_EPSS: 24,
    IntelSource.ATTACK_ENTERPRISE: 168,
    IntelSource.ATTACK_ICS: 168,
    IntelSource.CISA_ICS: 24,
    IntelSource.NIST_NVD: 24,
}


class IntelDocId:
    """The fixed `_id` of the one-per-system documents of the intelligence collections."""

    SWITCH: Final = "switch"  # tsg_external_feed_status: the runtime on/off switch
    ACTIVE_SNAPSHOT: Final = "active"  # tsg_external_intelligence_snapshots: the pointer to the active one


class EvidenceLimits:
    """How much evidence one threat gets and how big its search is."""

    PER_THREAT: Final = 3  # evidence records kept for one threat
    CANDIDATES: Final = 6  # records reranked per threat: the rerank cost is threats x this x text length
    QUERY_MAX_CHARS: Final = 700  # the search text of one threat, cut from the end (type, name, reason lead)
    MAX_FACTS: Final = 6  # plain sentences kept per evidence record
    DESCRIPTION_MAX_CHARS: Final = 320  # the attacker's behaviour, in the source's own words
    REAL_WORLD_USERS: Final = 2  # named groups / malware per technique
    MITIGATIONS: Final = 3
    RANGES_SAID: Final = 2  # affected version ranges and fixed versions put in one sentence
    VERSION_MAX_CHARS: Final = 40  # a version longer than this, or with odd characters, is not said
    SEARCHES_AT_ONCE: Final = 8  # reranker calls in flight for one batch


class TextSafety:
    """Source text is untrusted: it reaches an AI prompt, so it is cut to these sizes, stripped of control
    characters, and quarantined when it reads as instructions to an AI."""

    MAX_TEXT_CHARS: Final = 2_000  # the indexed text of one record
    MAX_TITLE_CHARS: Final = 200
    MAX_URL_CHARS: Final = 500
    MAX_DATA_TEXT_CHARS: Final = 600  # any one string inside `IntelRecord.data`
    MAX_DATA_ITEMS: Final = 50  # any one list inside `IntelRecord.data`
    MAX_FACT_CHARS: Final = 320  # one plain sentence handed to the scenario writer


class EvidenceReason(StrEnum):
    """Why a candidate was left out, written for the reviewer who opens a threat's search audit."""

    BELOW_THRESHOLD = "Scored {score:.0f} of 100, under the {threshold:.0f} needed."
    DIFFERENT_PRODUCT = "Concerns {vendor} {product}; the asset records none of that vendor or product."
    OTHER_PRODUCT_OF_VENDOR = "Concerns {vendor} {product}; the asset records only other products."
    NO_PRODUCT_LINK = "Concerns a specific product; nothing the asset records ties the asset to it."
    DUPLICATE = "The same record is already used for this threat."
    OVER_LIMIT = "More relevant records already fill the {limit} places for this threat."
    VERSION_NOT_AFFECTED = "Concerns {vendor} {product}; the asset's recorded version is not an affected one."


class EvidenceFact(StrEnum):
    """Plain sentences the scenario writer may use. Never an id: ids live only in `Evidence.ref`."""

    USED_BY = "{name}, {what}, has used this technique."
    CAMPAIGN_USED = "The {name} campaign used this technique."
    MITIGATED_BY = "It can be reduced by: {mitigations}."
    KEV_LISTED = "CISA lists weaknesses in {vendor} {product} as exploited in real attacks (added {date})."
    KEV_LISTED_UNNAMED = "CISA lists a weakness as exploited in real attacks (added {date})."
    RANSOMWARE = "Ransomware groups are known to have used it."
    LIKELIHOOD = "It scored {percent}% likelihood of exploitation in the next 30 days."
    ADVISORY = "A CISA advisory for {product} describes {impact}."
    ADVISORY_UNNAMED = "A CISA advisory describes {impact}."
    ADVISORY_IMPACT = "security weaknesses that could be exploited"
    VERSIONS_AND_FIXED = "It affects versions {ranges}; fixed in {fixed}."
    VERSIONS_ONLY = "It affects versions {ranges}."
    FIXED_ONLY = "It is fixed in {fixed}."
    SEVERITY = "Its seriousness is rated {severity} ({score} of 10)."
    SEVERITY_WORD = "Its seriousness is rated {severity}."


class VersionWords(StrEnum):
    """How an affected version range is said in plain words (evidence facts)."""

    FROM = "from {version}"
    AFTER = "after {version}"
    UP_TO = "up to {version}"
    BEFORE = "before {version}"
    AND_LATER = "{version} and later"


#: Lower bound of a 0-10 score and the word for it, highest first. Scores under the last bound say nothing.
SEVERITY_BANDS: Final = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))

#: How a source names the kind of actor behind a technique (ATT&CK groups, software, campaigns).
ACTOR_KIND_WORDS: Final[dict[str, str]] = {
    "group": "a threat group",
    "software": "a piece of malicious software",
}
