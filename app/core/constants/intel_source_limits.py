"""External intelligence: the numbers of the source readers, the text cleaner, the rerank gate and the stores.

Split from external_intelligence.py (the 300-line file limit, constants included). Every value here was a
private number beside its code; the code now reads it from here."""

from typing import Final


class SourceDownload:
    """What one download and one parse may cost. A body or a stream over these is not the source's file."""

    MAX_BYTES: Final = 256 * 1024 * 1024  # one HTTP body; the largest source (ATT&CK) is about 40 MB
    #: One JSON or CSV text handed to a parser, or a gunzipped stream.
    MAX_PARSED_BYTES: Final = 128 * 1024 * 1024
    CHUNK_BYTES: Final = 1024 * 1024
    MAX_RETRY_AFTER_SECONDS: Final = 60  # the longest "retry-after" a busy server is believed
    #: What each source's file may weigh (each below MAX_BYTES, which stays the cap of any other download).
    MAX_KEV_BYTES: Final = 64 * 1024 * 1024
    MAX_ATTACK_BYTES: Final = 64 * 1024 * 1024
    MAX_ICS_FILE_BYTES: Final = 2 * 1024 * 1024  # one advisory
    MAX_ICS_CHANGES_BYTES: Final = 1024 * 1024  # changes.csv
    MAX_NVD_PAGE_BYTES: Final = 50 * 1024 * 1024
    MAX_REDIRECTS: Final = 3


class SourceHosts:
    """Where a source's links and redirects may lead. A host matches itself and its subdomains."""

    #: A download may be redirected to its own host or to one of these (https only).
    REDIRECTS: Final = ("raw.githubusercontent.com", "cisa.gov", "www.cisa.gov", "epss.empiricalsecurity.com")
    CISA_PAGES: Final = ("cisa.gov",)
    ATTACK_PAGES: Final = ("attack.mitre.org",)
    #: The canonical page of a record, built from its id when the source's own link is not on its host.
    CISA_ADVISORY_PAGE: Final = "https://www.cisa.gov/news-events/ics-advisories/{advisory_id}"
    ATTACK_TECHNIQUE_PAGE: Final = "https://attack.mitre.org/techniques/{path}"
    ATTACK_GROUP_PAGE: Final = "https://attack.mitre.org/groups/{group_id}/"


class KevReading:
    """Characters kept of one CISA KEV entry."""

    VENDOR_PRODUCT_CHARS: Final = 100
    DESCRIPTION_CHARS: Final = 700
    ACTION_CHARS: Final = 300


class EpssReading:
    MAX_ROWS: Final = 2_000_000  # the real file has about 250k: a stream of more is not this file
    FIRST_LINE_BYTES: Final = 1024  # the "#model_version:...,score_date:..." line is far shorter
    MARKER_HEX_CHARS: Final = 12  # characters of the wanted-CVE hash kept in the checkpoint marker


class AttackReading:
    """How much of one ATT&CK object is kept."""

    #: What the reader keeps of a file. A checkpoint made by another format reads the file again (G230: the
    #: groups behind each technique are kept now, 2; a group's kind read from its origin too, 3; the places
    #: and sectors a group attacked, 4 (G232); what a group IS is never whom it attacked, 5; an unchanged
    #: file would otherwise never be read again).
    FORMAT: Final = "5"
    REAL_WORLD_USE_LIMIT: Final = 5
    MITIGATIONS_IN_TEXT: Final = 5
    TEXT_LIMIT: Final = 1500  # characters of the search text that the technique's own description may use
    TAIL_ROOM: Final = 250  # tactics, platforms and mitigations follow the description
    NOTE_CHARS: Final = 200
    LABEL_CHARS: Final = 60


class IcsReading:
    """How much of one CISA ICS advisory is kept, and how often a failing file is retried."""

    SUMMARY_CHARS: Final = 450
    MITIGATION_CHARS: Final = 300
    NAME_CHARS: Final = 100
    WORDING_CHARS: Final = 100
    MAX_PRODUCTS: Final = 5_000
    MAX_MITIGATIONS: Final = 5
    MAX_FAILED_RUNS: Final = 3  # runs a file may fail in before it is rejected instead of retried
    MAX_FAILED_FILES: Final = 50  # failed files remembered in the checkpoint


class TextCleaning:
    """The untrusted-text cleaner and the blob checks."""

    RAW_FACTOR: Final = 8  # characters read per kept character: cleaning shrinks text, a prefix is enough
    MIN_RAW_CHARS: Final = 4_096
    MAX_ROUNDS: Final = 4  # normalise + strip rounds until the text is stable
    TOKEN_MAX_CHARS: Final = 47  # a longer run is no identifier: it is sanitised, and a blob is refused
    ENCODED_BLOB_MIN: Final = 48  # base64-like run of this many characters is an encoded payload
    MIXED_BLOB_MIN: Final = 32  # the same with digits, lower and upper case all present
    HEX_BLOB_MIN: Final = 40
    #: A long run split at "/", "_" and "-" into pieces this short is a path or a name, not base64.
    PATH_PIECE_MAX: Final = 24
    #: Hex lengths of the common digests (MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512): a hash in a report.
    DIGEST_HEX_LENGTHS: Final = (32, 40, 56, 64, 96, 128)
    #: A decoded run (a hash's bytes, a path read as base64) that is at least this share printable, or holds
    #: this many printable bytes in a row (a padded payload), is hidden text: random bytes have neither.
    DECODED_TEXT_SHARE: Final = 0.75
    DECODED_TEXT_RUN: Final = 10
    #: Scripts written beside Latin letters without a space ("IP" + Chinese): no look-alike of a Latin letter.
    ADJACENT_SCRIPTS: Final = ("CJK ", "HIRAGANA ", "KATAKANA ", "HANGUL ")
    #: Micro and ohm: a unit or a product name beside Latin letters.
    UNIT_LETTERS: Final = "\N{GREEK SMALL LETTER MU}\N{GREEK CAPITAL LETTER OMEGA}"
    VERSION_CHARS: Final = 64  # a product version longer than this is not compared


class FactWordLimits:
    MAX_TACTICS: Final = 4  # attacker goals put in one sentence
    #: A vendor, product, group, software or mitigation name longer than this is not a name.
    MAX_NAME_CHARS: Final = 60


class NameGrammar:
    """What a NAME field may look like. A name is a few capitalised words (APT28, Sandworm Team,
    Out-of-Band Communications Channel), not a sentence: an instruction typed into a name field fails here."""

    MAX_WORDS: Final = 7  # the longest real ATT&CK name, "Disable or Remove Feature or Program", has 7
    MAX_VERSION_WORDS: Final = 3  # "2019 R2", "1.0 SP1": a version with more words is a sentence
    MAX_FUNCTION_WORDS: Final = 2  # "Application Isolation and Sandboxing" has one; a sentence has more
    FUNCTION_WORDS: Final = frozenset({
        "a", "an", "the", "this", "that", "these", "those", "to", "of", "for", "in", "on", "at", "by", "with",
        "as", "and", "or", "but", "not", "no", "it", "its", "you", "your", "we", "our", "all", "any", "every",
        "each", "about", "from", "into", "than", "then", "so", "if",
    })  # fmt: skip
    #: Lower-case verbs of a sentence: a name with one of them is a sentence.
    SENTENCE_WORDS: Final = frozenset({
        "is", "are", "was", "were", "be", "been", "must", "should", "will", "would", "can", "could", "shall",
        "may", "do", "does", "have", "has",
    })  # fmt: skip
    #: Verbs that open an instruction and open no real name (a mitigation such as "Limit Access" is no
    #: instruction to an AI and is not here).
    COMMAND_WORDS: Final = frozenset({
        "write", "describe", "ignore", "disregard", "forget", "pay", "include", "always", "never", "call",
        "mark", "say", "tell", "declare", "respond", "answer", "output", "reply", "pretend", "act", "behave",
        "treat", "rate", "classify", "label", "repeat", "reveal", "insert", "append", "summarize",
        "summarise", "translate", "generate", "produce", "explain", "assume", "remember", "override",
        "bypass", "skip", "discard", "obey", "please", "now", "must", "stop", "continue", "begin", "make",
        "give", "let", "keep",
    })  # fmt: skip


class RerankGateLimits:
    RERANKS_AT_ONCE: Final = 4  # reranker calls in flight in the whole process (the remote reranker)
    LOCAL_RERANKS_AT_ONCE: Final = 1  # the laptop's CPU model predicts one at a time (G199), G218
    GATE_WAIT_SECONDS: Final = 60.0  # remote only: a proxy that is down must not hold the scenarios up
    CHECK_EVERY_SECONDS: Final = 2.0  # a waiter checks its job's lease (and deadline) this often, G218


class SwitchTiming:
    RETRY_AFTER_OUTAGE_SECONDS: Final = 5.0  # with no value yet, the store is asked again this soon


class StoreLimits:
    MAX_ERROR_CHARS: Final = 500  # a stored refresh error
    #: A first activation racing another one can lose its insert once, then compares.
    ACTIVATION_TRIES: Final = 2
