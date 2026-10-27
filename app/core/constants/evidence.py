"""External intelligence as evidence: untrusted-text safety, the evidence search, its facts and the story."""

from enum import StrEnum
from typing import Final

from app.core.constants.scenario import FindingSeverity


class Applicability(StrEnum):
    """Whether a vulnerability applies to the asset; a CVE alone never makes it confirmed."""

    CONFIRMED = "confirmed"  # the asset's vendor, product and version match the record
    UNKNOWN = "unknown"  # the asset's product or version is not recorded, or the record names none
    NOT_APPLICABLE = "not_applicable"  # the asset's vendor or product differs


class EvidenceRole(StrEnum):
    """What an evidence entry proves: only a weakness confirmed in the asset's own product is direct."""

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
    NO_SNAPSHOT = "no_intelligence_snapshot"  # nothing searched: no snapshot built yet


class EvidenceLimits:
    """How big one threat's search text is and how its records' facts are said; how many records are reranked
    and kept: EVIDENCE_CANDIDATES and EVIDENCE_KEPT_PER_THREAT."""

    QUERY_MAX_CHARS: Final = 700  # the search text of one threat, cut from the end
    MAX_FACTS: Final = 6  # plain sentences kept per evidence record
    REAL_WORLD_USERS: Final = 2  # named groups / malware per technique
    MITIGATIONS: Final = 3
    RANGES_SAID: Final = 2  # affected version ranges and fixed versions put in one sentence
    VERSION_MAX_CHARS: Final = 40  # a version longer than this, or with odd characters, is not said
    SEARCHES_AT_ONCE: Final = 8  # reranker calls in flight for one batch
    RERANKS_KEPT: Final = 2_000  # scored searches kept per process, the oldest dropped first


class RerankGateLimits:
    RERANKS_AT_ONCE: Final = 6  # reranker calls in flight in the whole process (the remote reranker)
    LOCAL_RERANKS_AT_ONCE: Final = 1  # the local CPU model predicts one at a time
    CHECK_EVERY_SECONDS: Final = 2.0  # a waiter checks its job's lease (and deadline) this often


class TextSafety:
    """Source text reaches an AI prompt: cut to these sizes, cleaned, quarantined if it instructs."""

    MAX_TEXT_CHARS: Final = 2_000  # the indexed text of one record
    MAX_TITLE_CHARS: Final = 200
    MAX_URL_CHARS: Final = 500
    MAX_DATA_ITEMS: Final = 50  # any one list inside `IntelRecord.data`
    MAX_FACT_CHARS: Final = 320  # one plain sentence handed to the scenario writer


class TextCleaning:
    """The untrusted-text cleaner and the blob checks."""

    RAW_FACTOR: Final = 8  # characters read per kept character: cleaning shrinks text, a prefix is enough
    MIN_RAW_CHARS: Final = 4_096
    MAX_ROUNDS: Final = 4  # normalise + strip rounds until the text is stable
    TOKEN_MAX_CHARS: Final = 47  # a longer run is no identifier: it is sanitised, and a blob is refused
    ENCODED_BLOB_MIN: Final = 48  # base64-like run of this many characters is an encoded payload
    MIXED_BLOB_MIN: Final = 32  # the same with digits, lower and upper case all present
    HEX_BLOB_MIN: Final = 40
    PATH_PIECE_MAX: Final = 24  # a long run split at "/", "_" and "-" into pieces this short is a path
    DIGEST_HEX_LENGTHS: Final = (32, 40, 56, 64, 96, 128)  # MD5 to SHA-512: a hash in a report
    DECODED_TEXT_SHARE: Final = 0.75  # a decoded run this share printable is hidden text ...
    DECODED_TEXT_RUN: Final = 10  # ... or one with this many printable bytes in a row
    ADJACENT_SCRIPTS: Final = ("CJK ", "HIRAGANA ", "KATAKANA ", "HANGUL ")  # written beside Latin, no space
    UNIT_LETTERS: Final = "\N{GREEK SMALL LETTER MU}\N{GREEK CAPITAL LETTER OMEGA}"  # micro and ohm
    VERSION_CHARS: Final = 64  # a product version longer than this is not compared


class FactWordLimits:
    MAX_TACTICS: Final = 4  # attacker goals put in one sentence
    MAX_NAME_CHARS: Final = 60  # a longer vendor, product, group, software or mitigation name is not a name


class NameGrammar:
    """What a name field may look like: a few capitalised words, never a sentence or an instruction."""

    MAX_WORDS: Final = 7  # the longest real ATT&CK name has 7
    MAX_VERSION_WORDS: Final = 3  # "2019 R2", "1.0 SP1": a version with more words is a sentence
    MAX_FUNCTION_WORDS: Final = 2
    FUNCTION_WORDS: Final = frozenset({
        "a", "an", "the", "this", "that", "these", "those", "to", "of", "for", "in", "on", "at", "by", "with",
        "as", "and", "or", "but", "not", "no", "it", "its", "you", "your", "we", "our", "all", "any", "every",
        "each", "about", "from", "into", "than", "then", "so", "if",
    })  # fmt: skip
    #: Verbs of a sentence: a name with one of them is a sentence.
    SENTENCE_WORDS: Final = frozenset({
        "is", "are", "was", "were", "be", "been", "must", "should", "will", "would", "can", "could", "shall",
        "may", "do", "does", "have", "has",
    })  # fmt: skip
    #: Verbs that open an instruction and open no real name.
    COMMAND_WORDS: Final = frozenset({
        "write", "describe", "ignore", "disregard", "forget", "pay", "include", "always", "never", "call",
        "mark", "say", "tell", "declare", "respond", "answer", "output", "reply", "pretend", "act", "behave",
        "treat", "rate", "classify", "label", "repeat", "reveal", "insert", "append", "summarize",
        "summarise", "translate", "generate", "produce", "explain", "assume", "remember", "override",
        "bypass", "skip", "discard", "obey", "please", "now", "must", "stop", "continue", "begin", "make",
        "give", "let", "keep",
    })  # fmt: skip


class EvidenceReason(StrEnum):
    """Why a candidate was left out, for the reviewer who opens a threat's search audit."""

    BELOW_THRESHOLD = "Scored {score:.0f} of 100, under the {threshold:.0f} needed."
    DIFFERENT_PRODUCT = "Concerns {vendor} {product}; the asset records none of that vendor or product."
    OTHER_PRODUCT_OF_VENDOR = "Concerns {vendor} {product}; the asset records only other products."
    NO_PRODUCT_LINK = "Concerns a specific product; nothing the asset records ties the asset to it."
    DUPLICATE = "The same record is already used for this threat."
    OVER_LIMIT = "More relevant records already fill the {limit} places for this threat."
    VERSION_NOT_AFFECTED = "Concerns {vendor} {product}; the asset's recorded version is not an affected one."


class EvidenceFact(StrEnum):
    """Plain sentences the scenario writer may use; never an id (ids live only in `Evidence.ref`)."""

    TACTICS = "It is used for these attacker goals: {tactics}."
    USED_BY = "{name}, {what}, has used this technique."
    CAMPAIGN_USED = "The {name} used this technique."  # `name` ends in "campaign"
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
    """How an affected version range is said in plain words."""

    FROM = "from {version}"
    AFTER = "after {version}"
    UP_TO = "up to {version}"
    BEFORE = "before {version}"
    AND_LATER = "{version} and later"


#: Lower bound of a 0-10 score and its word, highest first; a score under the last bound says nothing.
#: Who used a technique, as EvidenceFact.USED_BY and CAMPAIGN_USED say it; a campaign ATT&CK names only by
#: its id (C0027) is no name.
REAL_WORLD_USER: Final = (
    r"(?P<name>.+?), [^,]+, has used this technique\.|The (?P<campaign>(?!C\d{4} ).+) used this technique\."
)
SEVERITY_BANDS: Final = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))

#: How a source names the kind of actor behind a technique.
ACTOR_KIND_WORDS: Final[dict[str, str]] = {
    "group": "a threat group",
    "software": "a piece of malicious software",
}

#: THREAT_CONTEXT_COUNTRY as a deployment may write it -> the country.
PLACE_WORDS: Final[dict[str, str]] = {
    name: "United Arab Emirates"
    for name in (
        "united arab emirates", "uae", "u.a.e.", "emirati", "emirates", "abu dhabi", "dubai", "sharjah",
        "ajman", "fujairah", "ras al khaimah", "umm al quwain",
    )
}  # fmt: skip
#: The countries THREAT_CONTEXT_COUNTRY may name.
COUNTRY_REGIONS: Final = ("United Arab Emirates",)


class WriterStyle(StrEnum):
    """How a scenario is written; a regenerate keeps the style of the scenario it replaces while on."""

    ORIGINAL = "original"  # without external intelligence
    EVIDENCE_STORY = "evidence_story"  # the five-beat story ending in its cited precedent


class EvidenceMode(StrEnum):
    """content.evidence_mode: whether the story rests on source documents, on the nearest related ones, or is
    inferred from the asset."""

    SOURCE_DOCUMENTED = "source-documented"
    NEAREST = "nearest"  # none met the threshold: the closest records, only related
    INFERRED = "inferred"


class Precedent:
    """The sentence code cites in an evidence story when the writer's own passage cannot be: from the cited
    entry's own facts; and why the passage was not cited."""

    USED_BY: Final = 'In real-world attacks, {names} {verb} used the technique "{technique}"'
    # nearest evidence: only related, and said so
    USED_RELATED: Final = 'In real-world attacks, {names} {verb} used the related technique "{technique}"'
    RELATED_RECORD: Final = "A related record: {fact}"
    NOT_WRITTEN: Final = "none was written"
    TOO_LONG: Final = "over its {most}-word limit"
    NOT_PLAIN: Final = "it holds a marker, a redaction, a link, a code or an internal label"
    NOT_CONFIRMED: Final = "the reviewer did not confirm it against its source"


class EvidenceBlock:
    """The delimiters of a prompt's untrusted-evidence block; a fact containing one is stripped of it."""

    BEGIN: Final = "<<<UNTRUSTED_EVIDENCE_BEGIN>>>"
    END: Final = "<<<UNTRUSTED_EVIDENCE_END>>>"
    LOOK_ALIKES: Final = (
        "UNTRUSTED_EVIDENCE_BEGIN",
        "UNTRUSTED_EVIDENCE_END",
        "UNTRUSTED_EVIDENCE",
        "<<<",
        ">>>",
        "BRIEF:",
        "PLAN:",
        "SCENARIO:",
        "EVIDENCE:",
    )


class StoryFindingCode(StrEnum):
    """What the safety checks find in a scenario's markers and words."""

    UNKNOWN_MARKER = "unknown_marker"  # a [n] marker the writer wrote: only code cites
    INJECTION_ECHO = "injection_echo"  # the draft repeats an instruction aimed at an AI


STORY_FINDING_SEVERITIES: Final[dict[StoryFindingCode, FindingSeverity]] = {
    code: FindingSeverity.BLOCKER for code in StoryFindingCode
}


class StoryFindingMessage(StrEnum):
    UNKNOWN_MARKER = (
        "Uses the marker(s) {markers}, but the writer cites nothing: the platform adds any cited precedent "
        "itself. Remove each marker and the real-world claim it marks; tell it as what could happen to this "
        "asset."
    )
    INJECTION_ECHO = "Repeats text that reads as an instruction to an AI system. Remove it."


class RecordedFields:
    """The asset and system facts naming a vendor, product or version, read to tie evidence to the asset."""

    VENDOR_KEYS: Final = ("vendor_name",)
    PRODUCT_KEYS: Final = ("technology_used", "operating_system")
    VERSION_KEYS: Final = ("product_version", "firmware_version", "software_version")


#: Rerank models EVIDENCE_SIMILARITY_THRESHOLD is calibrated on (scripts/calibrate_evidence_threshold.py).
EVIDENCE_THRESHOLD_CALIBRATED_ON: Final[dict[str, str]] = {"bge-reranker-v2-m3": "2026-10-19"}


class EvidenceSettingMessage(StrEnum):
    THRESHOLD_NOT_SET = (
        "EVIDENCE_SIMILARITY_THRESHOLD must be set explicitly outside dev while "
        "EXTERNAL_INTELLIGENCE_ENABLED is true: each reranker model scores on its own scale "
        "(calibrate with scripts/calibrate_evidence_threshold.py)."
    )
