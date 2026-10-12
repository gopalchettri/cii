"""The threat and control libraries: categories, procedures, search and actor limits."""

from enum import StrEnum
from typing import Final


class AssetType(StrEnum):
    r"""Threat_Catalogue.AssetType and Control_Library.AssetType: where a threat or control applies (owner
    2026-10-12, G211: IT, OT or IT\OT, the last meaning both; "IT-OT" is not a value). Also an asset's and a
    system's category code."""

    IT = "IT"
    OT = "OT"
    IT_OT = r"IT\OT"


class StrideCategory(StrEnum):
    """The six STRIDE categories, in display order (definition order is the order)."""

    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


#: One-line definitions every category verdict is judged against (v1 prompts._STRIDE_DEFINITIONS, word for
#: word): in each relevance-gate and gap-fill prompt and at the head of each threat search query.
STRIDE_DEFINITIONS: Final[dict[StrideCategory, str]] = {
    StrideCategory.SPOOFING: "pretending to be another user, device or service to be trusted as them",
    StrideCategory.TAMPERING: "unauthorised modification of data, configuration, commands or code",
    StrideCategory.REPUDIATION: "an action that cannot be reliably attributed to whoever performed it",
    StrideCategory.INFORMATION_DISCLOSURE: "information exposed to someone not authorised to see it",
    StrideCategory.DENIAL_OF_SERVICE: "a service or capability made unavailable or degraded",
    StrideCategory.ELEVATION_OF_PRIVILEGE: "gaining access or rights beyond those that were granted",
}


class StoredProcedure(StrEnum):
    GET_ASSET_CONTEXT = "tsg_GetAssetContext"
    GET_THREAT_LIBRARY = "tsg_GetThreatLibrary"
    GET_CONTROL_LIBRARY = "tsg_GetControlLibrary"
    GET_LIBRARY_STAMP = "tsg_GetLibraryStamp"
    # The library writes (scripts/sql): promoted and hand-written threats, the curator's decisions, imports.
    RESOLVE_THREAT = "tsg_ResolveThreat"
    LIST_PENDING_THREATS = "tsg_ListPendingThreats"
    DECIDE_PENDING_THREATS = "tsg_DecidePendingThreats"
    IMPORT_THREAT_LIBRARY = "tsg_ImportThreatLibrary"


class LibrarySource(StrEnum):
    """Who proposed a library row (tsg_ResolveThreat @Source)."""

    AI = "ai"  # an AI-proposed threat a person promoted (#27)
    MANUAL = "manual"  # a hand-written scenario's new threat (Step 16)


class ResolveOutcome(StrEnum):
    """tsg_ResolveThreat's answer for one proposed threat."""

    CREATED_PENDING = "created_pending"  # inserted inactive: a curator decides (#24)
    EXISTING_ACTIVE = "existing_active"  # the name is live already: nothing written
    EXISTING_PENDING = "existing_pending"  # the name already waits for a curator: nothing written


class DecisionOutcome(StrEnum):
    """tsg_DecidePendingThreats's answer for one id (#24)."""

    APPROVED = "approved"
    REJECTED = "rejected"
    ALREADY_APPROVED = "already_approved"  # approved before this call: nothing changed
    ALREADY_REJECTED = "already_rejected"
    IS_APPROVED = "is_approved"  # asked to reject a live threat: refused, nothing changed
    NOT_FOUND = "not_found"


class Curation:
    MAX_IDS_PER_CALL: Final = 100  # ids per decisions call, both lists together (BLUEPRINT AD2)


class CurationMessage(StrEnum):
    NO_IDS = "Send at least one id to approve or reject."
    TOO_MANY = "At most {limit} ids per call; {count} were sent."
    IN_BOTH = "Ids {ids} are in both lists: approve or reject each one."
    REPEATED = "Ids {ids} are sent more than once."


class LibraryRowKind(StrEnum):
    """tsg_GetThreatLibrary result set 7: what a pending row is."""

    TYPE = "type"
    THREAT = "threat"


class Search:
    """v1's hybrid-search values (v1 app/pipeline/hybrid_search.py), kept so results match."""

    RRF_K: Final = 60  # reciprocal-rank fusion: a rank r is worth 1 / (60 + r)
    BM25_K1: Final = 1.5
    BM25_B: Final = 0.75
    # Vector leg: only rows at least this similar (cosine 0-1) take part when any reach it, else the best.
    VECTOR_FLOOR: Final = 0.60
    THREATS_PER_QUERY: Final = 10  # library threats each query shortlists for the AI relevance check
    QUERY_MAX_CHARS: Final = 1_500  # one search query (category + definition + sector + one part's facts)


class Actors:
    MIN: Final = 1
    # 1 acting actor + up to 3 alternates: the next linked actors, best fit first (owner 2026-10-10; the name
    # similarity check of 2026-10-08 is gone: no linked pair of the dev library reached it).
    MAX: Final = 4
