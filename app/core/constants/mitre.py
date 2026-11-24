"""The run POST /v1/mitre_create_session starts (ADR-010): MITRE data first, then the AI selects actors, plans
attack paths and writes one scenario per path, and code checks every ID against the stored MITRE STIX data."""

from enum import StrEnum
from typing import Final


class MitreStage(StrEnum):
    """tsg_sessions.mitre.stage: where a MITRE run is; stored only when it changes phase."""

    QUEUED = "queued"
    SELECTING_ACTORS = "selecting_actors"
    PLANNING = "planning"
    WRITING = "writing"
    COMPLETE = "complete"


class MitreMessage(StrEnum):
    """What a MITRE run tells the caller and the logs."""

    USE_MITRE_ROUTES = (
        "This run was started by POST /v1/mitre_create_session: regenerate its scenarios or write its next set "
        "with its own calls, POST /v1/mitre_sessions/.../regenerate/scenarios and .../scenarios/next-set."
    )
    NO_MITRE_DATA = (
        "The MITRE ATT&CK {domains} data is not imported yet, so no scenario can be grounded. Import it: POST "
        "/v1/tsg/intel/refresh, then GET /v1/tsg/intel/health until each source shows records."
    )
    NO_PATHS = "No attack path passed the MITRE checks for this asset: no scenario can be written."
    NO_SCENARIO = "No scenario passed the MITRE checks for this run's paths."
    NOTHING_LEFT = (
        "Every MITRE attack path of this run is done: {written} scenarios written, {dropped} dropped by the MITRE "
        "checks. {why}"
    )
    PLANNER_FOUND_EVERY_PATH = "The planner found no further relevant path."
    PLANNER_AT_ROUND_CAP = "The planner stopped at MITRE_PLANNER_MAX_FURTHER_ROUNDS."
    TARGET_REACHED = (
        "TOTAL_SCENARIO_COUNT ({target}) reached: {written} scenarios written, {dropped} dropped by the MITRE "
        "checks; {left_out} further MITRE attack paths were left out."
    )
    SET_STARTED = (
        "Writing the next set: up to {size} of the {remaining} scenarios left ({written} written, {dropped} dropped "
        "so far)."
    )
    SET_PLANNING_FIRST = (
        "Asking the MITRE planner for further relevant paths, then writing the next set ({written} written, "
        "{dropped} dropped so far)."
    )


class MitreProblem(StrEnum):
    """Why code refused part of an AI answer: an actor row or a plan (counted under this text), or a written
    scenario (sent back to the writer to fix)."""

    NOT_AN_OBJECT = "not an object"
    UNKNOWN_ACTOR = "unknown actor id"
    RELEVANCE_OUT_OF_RANGE = "relevance not {least}-{most}"
    QUOTE_TOO_SHORT = "quote shorter than {words} words"
    NO_REASON = "no reason"
    QUOTE_NOT_IN_DESCRIPTION = "quote not in the actor's MITRE description"
    INVENTED_ID_IN_REASON = "invented MITRE ID in the reason"
    TOO_FEW_TECHNIQUES = "fewer than {count} techniques"
    TOO_MANY_TECHNIQUES = "more than {count} techniques"
    NO_ICS_TECHNIQUE = "no ICS technique although the path attacks OT"
    NO_STRIDE_CATEGORY = "no STRIDE category"
    NO_DOCUMENTED_GROUP = "no MITRE group documented for these techniques"
    DUPLICATE_PATH = "duplicate of a higher-ranked path"
    SAME_SCENARIO = "the same target and result as a higher-ranked path"
    DUPLICATE_OF_UNKNOWN = "{id}: duplicate_of {duplicate_of} must be a planned id or a new id listed before it"
    CROSSING_MIXED_TYPES = "the asset and its supporting systems mix IT and OT"
    CROSSING_JUDGED_BY_PLANNER = "judged relevant by the planner"
    ANSWER_LAYOUT = 'the reply must be {{"{key}": [...]}}'
    WORD_LIMIT = "{field} exceeds the word limit: {words} words, the maximum is {maximum}; shorten it"
    SCHEMA_FAILED = "Schema validation failed: {location}: {error_type}"
    TECHNIQUE_NOT_PLANNED = (
        "attack technique {mitre_id} is not one of the planned techniques (stix_id and mitre_id must match)"
    )
    GROUP_NOT_A_CANDIDATE = "relevant group {name} ({mitre_id}) must be one of the supplied candidate_actors"
    GROUP_NOT_DOCUMENTED = "MITRE does not document {name} for any technique of this scenario"
    SYSTEM_NOT_THE_ASSETS = "supporting system {name} is not one of the asset supporting systems"
    THREAT_TYPE_NOT_LISTED = "threat_type must be one of threat_types, copied exactly"
    CROSSING_TECHNIQUES_DROPPED = "The plan crosses between IT and OT: keep both its Enterprise and ICS techniques"
    INVENTED_ID = "Invented MITRE ID {mitre_id}"
    DROPPED_ITEM_IN_TEXT = (
        "the scenario text names {name}, which is not a planned technique or a verified group: leave it out"
    )
    NO_SCENARIO_FOR_PATH = "no scenario was returned for this path (slot)"


#: The STIX objects one MITRE STIX collection keeps (tsg_mitre_enterprise_stix, tsg_mitre_ics_stix): every
#: object of these types, revoked and deprecated ones included (the index skips them, a relationship may name
#: them), and the relationships of these kinds.
MITRE_STIX_TYPES: Final = frozenset(
    {
        "attack-pattern",
        "intrusion-set",
        "campaign",
        "malware",
        "tool",
        "x-mitre-asset",
        "x-mitre-collection",
        "course-of-action",
    }
)
MITRE_STIX_RELATIONSHIP_TYPES: Final = frozenset({"uses", "mitigates", "attributed-to", "targets"})
#: Added to the version of STIX objects still being written: only a finished import stores the bare version.
MITRE_STIX_WRITING_MARK: Final = "|writing"
#: The fields of each kept object the engine reads; the rest of a STIX object is not stored.
MITRE_STIX_FIELDS: Final = (
    "id",
    "type",
    "name",
    "description",
    "external_references",
    "kill_chain_phases",
    "x_mitre_platforms",
    "revoked",
    "x_mitre_deprecated",
    "modified",
    "source_ref",
    "target_ref",
    "relationship_type",
    "x_mitre_related_assets",
    "x_mitre_is_subtechnique",
    "x_mitre_remote_support",
    "x_mitre_impact_type",
    "aliases",
    "first_seen",
    "last_seen",
    "x_mitre_sectors",
)
#: The asset input fields an actor's MITRE evidence may match: each selected actor reports them as
#: matched_fields, and a name outside this list is dropped.
MITRE_ASSET_FIELDS_TO_MATCH: Final = (
    "sector",
    "subsector",
    "service_name",
    "service_description",
    "asset_name",
    "asset_description",
    "asset_type",
    "data_handled",
    "supporting_systems",
)
