"""External intelligence in the writer and the worker: the writer's two styles, the story's limits and
findings, the untrusted-evidence block, the recorded fields an evidence search reads, and the
admin/worker words. The sources, records and limits are in external_intelligence.py."""

from enum import StrEnum
from typing import Final

from app.core.constants.writing import FindingSeverity


class WriterStyle(StrEnum):
    """How a scenario is written. ORIGINAL is the app as it was before external intelligence;
    EVIDENCE_STORY is the five-beat story with evidence markers. Decided per batch from the on/off
    switch; a regenerate keeps the style of the scenario it replaces."""

    ORIGINAL = "original"
    EVIDENCE_STORY = "evidence_story"


class EvidenceMode(StrEnum):
    """content.evidence_mode: whether the story rests on source documents or is inferred from the asset."""

    SOURCE_DOCUMENTED = "source-documented"
    INFERRED = "inferred"


class StoryLimits:
    MIN_SENTENCES: Final = 4  # one per beat at least, the last two may share a sentence
    PROMPT_VERSION: Final = "scenario writer-evidence-1"  # stored as content.prompt_version of a story


class EvidenceBlock:
    """The delimiters of the untrusted-evidence block of a prompt. A fact containing one is stripped of it."""

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
    """What the story rules find (engine/external_intelligence/story/evidence_story_rules.py). Kept apart from
    FindingCode so the original writer's codes stay exactly as they were."""

    UNKNOWN_MARKER = "unknown_marker"  # a [n] marker with no evidence n in the plan
    UNMARKED_PRECEDENT = "unmarked_precedent"  # a real-world name from the evidence without its marker
    BEATS_MISSING = "beats_missing"  # too few sentences for the five beats
    UNKNOWN_APPLICABILITY_CLAIM = "unknown_applicability_claim"  # "is vulnerable" on evidence that is unknown
    INJECTION_ECHO = "injection_echo"  # the draft repeats an instruction aimed at an AI


STORY_FINDING_SEVERITIES: Final[dict[StoryFindingCode, FindingSeverity]] = {
    code: FindingSeverity.BLOCKER for code in StoryFindingCode
}


class StoryFindingMessage(StrEnum):
    UNKNOWN_MARKER = "Uses the marker(s) {markers}, but the evidence has only entries 1 to {count}."
    UNMARKED_PRECEDENT = "Names {names} from the evidence without the marker of the entry that states it."
    BEATS_MISSING = (
        "The scenario has {sentences} sentences; it needs the five beats, one sentence each at least."
    )
    UNKNOWN_APPLICABILITY_CLAIM = (
        "States that the asset is vulnerable, exploitable or affected, but the evidence {markers} is not "
        "known to apply to it. Word it conditionally (for example 'if the asset runs ...')."
    )
    INJECTION_ECHO = "Repeats text that reads as an instruction to an AI system. Remove it."


class RecordedFields:
    """The asset and supporting-system facts that name a vendor, a product or its version (the procedure's own
    columns), read to tell whether an evidence record concerns the asset."""

    VENDOR_KEYS: Final = ("vendor_name",)
    PRODUCT_KEYS: Final = ("technology_used", "operating_system")
    VERSION_KEYS: Final = ("product_version", "firmware_version", "software_version")


#: Rerank models an operator has calibrated EVIDENCE_SIMILARITY_THRESHOLD on: model name (the last segment of
#: CII_RERANK_MODEL) -> date. Add a line after running scripts/calibrate_evidence_threshold.py on that model.
EVIDENCE_THRESHOLD_CALIBRATED_ON: Final[dict[str, str]] = {"bge-reranker-v2-m3": "2026-10-12"}


class EvidenceSettingMessage(StrEnum):
    THRESHOLD_NOT_SET = (
        "EVIDENCE_SIMILARITY_THRESHOLD must be set explicitly outside dev while "
        "EXTERNAL_INTELLIGENCE_ENABLED is true: each reranker model scores on its own scale "
        "(calibrate with scripts/calibrate_evidence_threshold.py)."
    )


class IntelWorkEvent(StrEnum):
    """Log events of the worker's intelligence code."""

    WARM_UP_FAILED = "external_intelligence.warm_up_failed"
    WARM_UP_SKIPPED = "external_intelligence.warm_up_skipped"
    REFRESH_SKIPPED = "external_intelligence.refresh_skipped"
    REFRESH_JOB_FAILED = "external_intelligence.refresh_job_failed"
    STAMP_FAILED = "external_intelligence.stamp_failed"
    EVIDENCE_NOT_SAVED = "external_intelligence.evidence_not_saved"
    RUNTIME_MISSING = "external_intelligence.runtime_missing"
    RELEVANCE_SKIPPED = "external_intelligence.country_relevance_skipped"  # G232: planned without it
    SWITCH_UNREADABLE = "external_intelligence.switch_unreadable"


class IntelRefreshMessage(StrEnum):
    """What an intelligence refresh request answers (same pattern as the embeddings build)."""

    IN_PROGRESS = "An intelligence refresh is already queued or running: details.job_id names it."
    NOT_SENT = "The job queue is unreachable: the refresh was not started. Try again shortly."
    SOURCE_NOT_APPROVED = "The source '{source}' is not approved; approve it before refreshing it."
    SWITCH_OFF = "External intelligence is off: nothing was refreshed."
