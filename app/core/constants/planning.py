"""The threat and control libraries, the asset's facts, threat finding and control mapping."""

from enum import StrEnum
from typing import Final

from app.core.constants.common import EmbeddingCorpus
from app.core.constants.jobs import Generation


class AssetType(StrEnum):
    r"""Where a library threat or control applies (IT\OT is both); also an asset's and a system's category."""

    IT = "IT"
    OT = "OT"
    IT_OT = r"IT\OT"


class StrideCategory(StrEnum):
    """The six STRIDE categories; definition order is the display order."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


#: What each category means: in each relevance-gate and gap-fill prompt and at the head of each threat search.
STRIDE_DEFINITIONS: Final[dict[StrideCategory, str]] = {
    StrideCategory.SPOOFING: "pretending to be another user, device or service to be trusted as them",
    StrideCategory.TAMPERING: "unauthorised modification of data, configuration, commands or code",
    StrideCategory.REPUDIATION: "an action that cannot be reliably attributed to whoever performed it",
    StrideCategory.INFORMATION_DISCLOSURE: "information exposed to someone not authorised to see it",
    StrideCategory.DENIAL_OF_SERVICE: "a service or capability made unavailable or degraded",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "gaining access or rights beyond those that were granted",
}


class StoredProcedure(StrEnum):
    GET_SERVICE_MAPPER_ASSOCIATIONS = "tsg_GetServiceMapperAssociations"
    GET_SECTORS_AND_SUBSECTORS = "Onboarding_GetSectorsAndSubsectorsList"
    GET_SECTOR_SERVICE_MAPPINGS = "Onboarding_GetSectorServiceMappings"
    GET_SERVICES_WITH_SECTOR_DETAILS = "Onboarding_GetServicesWithSectorDetails"
    GET_ASSET_CONTEXT = "tsg_GetAssetContext"
    GET_THREAT_LIBRARY = "tsg_GetThreatLibrary"
    GET_CONTROL_LIBRARY = "tsg_GetControlLibrary"
    GET_LIBRARY_STAMP = "tsg_GetLibraryStamp"
    RESOLVE_THREAT = "tsg_ResolveThreat"
    LIST_PENDING_THREATS = "tsg_ListPendingThreats"
    DECIDE_PENDING_THREATS = "tsg_DecidePendingThreats"
    IMPORT_THREAT_LIBRARY = "tsg_ImportThreatLibrary"


class LibrarySource(StrEnum):
    """Who proposed a library row (tsg_ResolveThreat @Source)."""

    AI = "ai"  # an AI-proposed threat a person promoted
    MANUAL = "manual"  # a hand-written scenario's new threat


class ResolveOutcome(StrEnum):
    """tsg_ResolveThreat's answer for one proposed threat."""

    CREATED_PENDING = "created_pending"  # inserted inactive: a curator decides
    EXISTING_ACTIVE = "existing_active"  # the name is live already: nothing written
    EXISTING_PENDING = "existing_pending"  # the name already waits for a curator: nothing written
    CURATOR_REJECTED = "curator_rejected"  # a curator rejected the name: nothing written, no ids


class DecisionOutcome(StrEnum):
    """tsg_DecidePendingThreats's answer for one id."""

    APPROVED = "approved"
    REJECTED = "rejected"
    ALREADY_APPROVED = "already_approved"  # approved before this call: nothing changed
    ALREADY_REJECTED = "already_rejected"
    IS_APPROVED = "is_approved"  # asked to reject a live threat: refused, nothing changed
    NOT_FOUND = "not_found"


class Curation:
    MAX_IDS_PER_CALL: Final = 100  # ids per decisions call, both lists together


class CurationMessage(StrEnum):
    NO_IDS = "Send at least one id to approve or reject."
    TOO_MANY = "At most {limit} ids per call; {count} were sent."
    IN_BOTH = "Ids {ids} are in both lists: approve or reject each one."
    REPEATED = "Ids {ids} are sent more than once."


class LibraryRowKind(StrEnum):
    """What a pending row of tsg_GetThreatLibrary result set 7 is."""

    TYPE = "type"
    THREAT = "threat"


class Search:
    """The hybrid search's values."""

    RRF_K: Final = 60  # reciprocal-rank fusion: a rank r is worth 1 / (60 + r)
    BM25_K1: Final = 1.5
    BM25_B: Final = 0.75
    VECTOR_FLOOR: Final = 0.60  # the vector leg keeps rows at least this similar when any reach it


#: What a search of each corpus asks, in English: sent before the query to a model with a query instruction
#: (EmbeddingModelProfile.query_instruction).
QUERY_TASKS: Final[dict[EmbeddingCorpus, str]] = {
    EmbeddingCorpus.THREAT: "Given a proposed threat, retrieve the library threats that are the same threat",
    EmbeddingCorpus.THREAT_TYPE: "Given a threat type name, retrieve the threat types with the same meaning",
    EmbeddingCorpus.THREAT_ACTOR: "Given a cyber threat, retrieve the threat actors likely to carry it out",
    EmbeddingCorpus.CONTROL: "Given a threat scenario, retrieve the security controls that mitigate it",
    EmbeddingCorpus.SERVICE: (
        "Given a description of a service or of what flows to or from it, retrieve the catalog services that "
        "match it"
    ),
    EmbeddingCorpus.EXTERNAL_INTELLIGENCE: (
        "Given a cyber threat, retrieve the threat intelligence records (attack techniques, exploited "
        "vulnerabilities, advisories) that show it"
    ),
}


class ContextProperties:
    """The columns of dbo.tsg_GetAssetContext: every one but these is a fact of the asset or a system."""

    # every asset and system row must return them
    HEAD: Final[tuple[str, ...]] = ("id", "name", "category_code")
    OPTION_COLUMNS: Final[tuple[str, ...]] = ("code", "name")  # a dropdown name's columns (part 5) ...
    # ... and the number its facts hold, under either name
    OPTION_KEYS: Final[tuple[str, ...]] = ("value", "id")
    ALWAYS_USED: Final[tuple[str, ...]] = (*HEAD, "alias")  # never a required fact: always there
    # an asset column about the whole organisation, not this asset
    ORGANISATION_PREFIX: Final[str] = "entity_"
    ORGANISATION_BRIEF_KEY: Final[str] = (
        "organisation_background_not_this_asset"  # the brief's key for those facts
    )
    COUNTRY_KEY: Final[str] = "country"  # THREAT_CONTEXT_COUNTRY, read while external intelligence is on
    UNNAMED_SYSTEM: Final[str] = "Supporting system {id}"  # a linked system not sent, saved without a name
    # the request field a refusal names for the facts the request decides
    REQUEST_FIELDS: Final[dict[str, str]] = {
        "sector": "sector_id",
        "sub_sector": "subsector_id",
        "critical_service": "service_id",
    }


class PropertyMessage(StrEnum):
    ALWAYS_USED = "{setting} names {names}: always used, so never a required fact. Remove them."
    NOT_RETURNED = (
        "{setting} names {names}, which dbo.tsg_GetAssetContext does not return: add the column to the "
        "procedure or remove the name from the setting."
    )
    HEAD_MISSING = "dbo.tsg_GetAssetContext must return {columns} in its {rows} rows; it does not."
    OPTIONS_OUT_OF_DATE = (
        "dbo.tsg_GetAssetContext's dropdown names (part 5) must return code, name and value (or id), not "
        "{found}. Fix the procedure's part 5."
    )
    RESERVED = (
        "dbo.tsg_GetAssetContext returns {columns} in its {rows} rows: reserved names, never shown to the "
        "AI. Rename them with AS (e.g. AS asset_criticality)."
    )
    REQUIRED_MISSING = "Required properties are not recorded: {gaps}."
    NOT_RECORDED = "{owner}: {names} not recorded."


class ThreatFinding:
    SYSTEM_NAME_CHARS: Final = 80  # a system's name is shown whole up to this; the AI answers by alias
    ORGANISATION_LABEL: Final = "ORGANISATION (the owner's whole estate, background only, NOT this asset): "
    GAP_FILL_MAX_CHARS: Final = 3_500  # a gap-fill proposal's type + threat
    LIBRARY_MATCH_CANDIDATES: Final = 10  # hybrid hits reranked against one proposal
    AI_DUPLICATE_COSINE: Final = 0.98  # an AI threat this close to a kept threat is a rewording of it
    CATEGORIES_AT_ONCE: Final = 6  # STRIDE categories judged in parallel
    AI_BATCHES_AT_ONCE: Final = 8  # gate batches of all categories share one pool this size
    REASON_MAX_CHARS: Final = 500
    IMPACT_RANK: Final[dict[str, int]] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}  # the gate's impact, higher first
    SYSTEM_ALIAS: Final = "SYS"  # SYS1, SYS2 ... in prompts; never a database id
    RECORD_SLOT: Final = "R"  # R1 ... in the relevance gate
    NEEDS_MAX_ITEMS: Final = 5  # what a verdict says a threat needs that nothing recorded mentions ...
    NEED_MAX_CHARS: Final = 80  # ... each cut to this


class ActorRole(StrEnum):
    ACTING = "acting"  # carries out the scenario: exactly one per threat


class AttackerCheck(StrEnum):
    """How a threat's acting attacker was decided."""

    CHOSEN = "chosen"  # the gate's pick, from the threat's own list, with its reason
    BALANCED = "balanced"  # older plans only: rated as suitable as the pick, acting for fewer threats
    NONE_FITS = "none_fits"  # the gate found no listed attacker plausible: the threat is not planned
    NOT_CHECKED = "not_checked"  # the gate gave no usable pick: the top-ranked linked actor acts
    RANKED = "ranked"  # older plans only: never judged by the gate, the ranking decided


class CandidateRejection(StrEnum):
    """Why a candidate threat of a category was not used."""

    NOT_RELEVANT = "not_relevant"
    NEEDS_UNRECORDED = "needs_unrecorded"  # relevant only by assuming something nothing recorded mentions
    ASSET_TYPE_MISMATCH = "asset_type_mismatch"  # judged to apply only where its AssetType cannot be


class PlanMessage(StrEnum):
    """A plan's refusals and notes, written for a reviewer."""

    ACTOR_LIBRARY_EMPTY = (
        "No threat type in the library links an active threat actor, so no scenario can name its attacker. "
        "Link at least one active threat actor to a threat type and start the run again."
    )
    PLAN_NOTE = "{planned} attack paths selected; {written} written, {remaining} still to write, set by set."
    AI_COULD_NOT_ANSWER = "The AI could not answer. Start a new session later."


class AnswerProblem(StrEnum):
    """Why an AI answer item breaks its contract: quoted to the AI in the re-ask."""

    GAP_FILL_INCOMPLETE = "AI fallback applies=true requires threat_type, threat and attacker"
    TEXT_REQUIRED = "must not be empty"
    RULE_VERDICTS_REQUIRED = (
        'every numbered rule needs a verdict: "holds", or broken: "<the exact words of the scenario>" '
        "- <reason>"
    )
    ENTRY_POINT_NOT_OFFERED = "entry_point must be one of entry_point_options, copied exactly: {options}"
    SYSTEM_REASONS_MISSING = "system_reasons must give one short sentence for each of: {names}"


class Controls:
    QUERY_MAX_CHARS: Final = 4_000  # one scenario's control query, cut from the end
    QUERY_MITIGATIONS: Final = 6  # the cited evidence's mitigations the query's head carries
    AI_DOMAIN: Final = "Artificial Intelligence & Autonomous Technologies"  # mapped only to an AI threat
    AI_THREAT_WORDS: Final = (  # a threat type or name about AI; acronyms match case-sensitively
        r"\b(?:AI|GenAI|LLMs?|ML)\b|(?i:artificial intelligence|machine learning|large language model)"
    )
    MAX_ATTEMPTS: Final = 5  # then failed for good; the sweep retries only a failure with attempts left
    LEASE_SECONDS: Final = 120  # one scenario's mapping, and a run's delivery, renewed while it runs
    RETRY_FAILED_AFTER_SECONDS: Final = 1_800
    SWEEP_EVERY_SECONDS: Final = 300
    RESEND_QUEUED_AFTER_SECONDS: Final = 600  # a queued mapping no worker took: its message was lost
    PER_DELIVERY: Final = Generation.WRITER_BATCH  # mappings one delivery makes before the run's next turn


class ControlMessage(StrEnum):
    NEAREST_ONLY = (
        "No control reached the control similarity threshold of {cutoff:g}; the {nearest} nearest compatible "
        "controls are kept (NEAREST_CONTROLS)."
    )
    STRONG_REASON = "Score {score:.0f} is at or above the threshold of {cutoff:g}: strong."
    FALLBACK_REASON = (
        "Score {score:.0f} is below the threshold of {cutoff:g}: fallback, among the nearest kept to reach "
        "the minimum of {least}."
    )
    NEAREST_REASON = (
        "Score {score:.0f} is below the threshold of {cutoff:g}: fallback, one of the {nearest} nearest kept "
        "because no control reached it."
    )
    SHORTFALL = "{kept} control(s) kept: the minimum is {least}, but only {kept} compatible control(s) exist."
    OTHER_TYPE = (
        "No control of asset type(s) {types} exists; the nearest control(s) of another type are kept: check "
        "that they fit."
    )
    OTHER_TYPE_REASON = (
        "Score {score:.0f}, asset type {asset_type}: another type than the scenario's, one of the {nearest} "
        "nearest kept: check that it fits."
    )


class ControlMatch(StrEnum):
    EXACT = "exact"  # scored at or above the reranker's control cut-off
    NEAREST = "nearest"  # none reached it: the nearest compatible controls, with a warning
    GIVEN = "given"  # named by the person for a hand-written scenario, in the order given


#: The selection tier of each match (the results' match tier).
CONTROL_TIERS: Final[dict[str, str]] = {
    ControlMatch.EXACT: "strong",
    ControlMatch.NEAREST: "fallback",
    ControlMatch.GIVEN: "given",
}
#: Why a control was kept for a scenario, in words (the results' match_reason).
CONTROL_MATCH_REASONS: Final[dict[str, str]] = {
    ControlMatch.EXACT: "Scored at or above the control similarity threshold for this scenario.",
    ControlMatch.NEAREST: "No control reached the threshold; this is the nearest relevant library control.",
    ControlMatch.GIVEN: "Named by the person who wrote this scenario.",
}

#: The library AssetTypes that fit an asset or system of each category; an untyped row fits everywhere.
COMPATIBLE_ASSET_TYPES: Final[dict[str, frozenset[str]]] = {
    AssetType.IT: frozenset({AssetType.IT, AssetType.IT_OT}),
    AssetType.OT: frozenset({AssetType.OT, AssetType.IT_OT}),
    AssetType.IT_OT: frozenset({AssetType.IT, AssetType.OT, AssetType.IT_OT}),
}
