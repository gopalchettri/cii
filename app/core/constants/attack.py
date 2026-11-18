"""The run POST /v1/create_session starts: the MITRE ATT&CK graph in MongoDB that confirms what the AI names,
the links from ATT&CK mitigations to library controls, and the controls picked per sentence."""

from enum import StrEnum
from typing import Final

from app.core.constants.intelligence import IntelSource


class RunPipeline(StrEnum):
    """tsg_sessions.pipeline: how a run's scenarios are made; a run without it finds library threats first."""

    ATTACK = "attack"  # the AI writes them from its ATT&CK knowledge, the graph in MongoDB confirms them


class AttackRecord(StrEnum):
    """tsg_attack.record: what one document is."""

    OBJECT = "object"  # a group, technique, mitigation, software or campaign
    RELATIONSHIP = "relationship"  # a link between two objects


class AttackObjectType(StrEnum):
    """tsg_attack.type of an object: its STIX type."""

    GROUP = "intrusion-set"
    TECHNIQUE = "attack-pattern"
    MITIGATION = "course-of-action"
    MALWARE = "malware"
    TOOL = "tool"
    CAMPAIGN = "campaign"


class AttackLink(StrEnum):
    """tsg_attack.type of a relationship: its STIX relationship_type."""

    USES = "uses"  # a group, software or campaign uses a technique
    MITIGATES = "mitigates"  # a mitigation reduces a technique
    ATTRIBUTED_TO = "attributed-to"  # a campaign is a group's


#: The ATT&CK matrix each source holds, as a message names it.
ATTACK_MATRIX_NAMES: Final[dict[str, str]] = {
    IntelSource.ATTACK_ENTERPRISE: "Enterprise",
    IntelSource.ATTACK_ICS: "ICS",
}


class AttackMessage(StrEnum):
    """What the ATT&CK check tells the caller, the AI (a re-ask's problem lines) and the plan trace."""

    NO_DATA = (
        "MITRE ATT&CK is not imported yet, so no scenario can be confirmed. Import it: POST "
        "/v1/tsg/intel/refresh, then GET /v1/tsg/intel/health until each source shows records."
    )
    NOT_FOUND = "{name} is not in MITRE ATT&CK {matrix}."
    NAME_NOT_UNIQUE = "{name} matches more than one MITRE ATT&CK entry: give its ATT&CK ID."
    NAME_MISMATCH = "{attack_id} is {found} in MITRE ATT&CK, not {given}: give the ID and the name of one entry."
    WRONG_KIND = "{name} is a MITRE ATT&CK {found}, not a {wanted}."
    SLOT_MISSING = "the reply held no item for this slot"
    CATEGORY_NOT_LISTED = "threat_category must be one of THREAT_CATEGORIES, copied exactly"
    TYPE_NOT_LISTED = "threat_type must be one of THREAT_TYPES, copied exactly"
    NO_GROUP = "The scenario names no threat group that MITRE ATT&CK holds."
    NO_TECHNIQUE = "The scenario names no technique that MITRE ATT&CK {matrix} holds."
    SCENARIO_NOT_CONFIRMED = "MITRE ATT&CK does not confirm this scenario ({problems}): it is not shown."
    USED_BY = "MITRE ATT&CK records that {group} uses {technique}."
    IS_TECHNIQUE = "{technique} is a technique of MITRE ATT&CK {matrix}."  # when no use by the group is recorded


class AttackCard:
    """What a card of an attack run shows of its confirmed scenario."""

    CITED_TECHNIQUES: Final = 3  # its evidence entries at most, the techniques the group is recorded using first


class ControlEffect(StrEnum):
    """How a control helps against what a mitigation or a sentence describes."""

    PREVENT = "prevent"  # the attack step cannot proceed
    DETECT = "detect"  # the step is seen
    CONTAIN = "contain"  # its spread or effect is limited
    RECOVER = "recover"  # what was lost is restored


class ControlLinks:
    """Linking each ATT&CK mitigation to library controls in the background, then picking a written set's
    controls per sentence in one AI call."""

    CANDIDATES: Final = 30  # one mitigation's nearest library controls, IT and OT together
    JUDGED: Final = 15  # the best reranked of them, judged by the AI
    DESCRIPTION_CHARS: Final = 1_200  # of a mitigation's ATT&CK description, searched and judged
    JUDGE_TEXT_CHARS: Final = 300  # of a control's description, in the linking call
    SHORTLIST: Final = 12  # a scenario's controls offered to the pick call
    PER_SENTENCE: Final = 2  # picks kept on one sentence
    MEANING_HITS: Final = 3  # nearest controls per sentence, by meaning
    CARD_TEXT_CHARS: Final = 120  # of a control's description, in the pick call
    LABEL_PREFIX: Final = "C"  # a control's label in a prompt (C1, C2 ...): no library id reaches the AI
    SCENARIO_SENTENCE_PREFIX: Final = "S"  # S1, S2 ...: the sentences of the scenario statement
    RISK_SENTENCE_PREFIX: Final = "R"  # R1, R2 ...: the sentences of the risk statement
    #: Listed by ATT&CK as mitigations, yet they mitigate nothing ("Mitigation Limited or Not Effective",
    #: "Do Not Mitigate", "Pre-compromise").
    NOT_MITIGATIONS: Final = frozenset({"M0816", "M1055", "M1056"})
    LOCK_KEY: Final = "tsg:control_links:lock"  # Redis: one linking run at a time
    LOCK_SECONDS: Final = 900  # the lock's life; a killed run frees it this soon
    LOCK_RENEW_SECONDS: Final = 120  # a running one renews it this often
    AFTER_IMPORT: Final = "import"  # requested_by of the preparation an import starts by itself
    WAIT_TURN_SECONDS: Final = 60  # that preparation asks again this often while another one is active


class ControlLinkOutcome(StrEnum):
    """What one linking run did to a mitigation (the job result's counts)."""

    JUDGED = "judged"  # reranked and judged by the AI, its links saved
    UNCHANGED = "unchanged"  # the same text, candidates, prompt and models as stored: no AI call
    FAILED = "failed"  # an outage or an unusable answer: its earlier links stay


class ControlLinkMessage(StrEnum):
    IN_PROGRESS = "A control-links preparation is already queued or running: details.job_id names it."
    NOT_SENT = "The job queue is unreachable: the preparation was not started. Try again shortly."
    BUSY = "Another control-links preparation holds the lock: this one did nothing."
    SWITCH_OFF = "External intelligence is off: nothing was prepared."
    MATCHES_NOT_A_LIST = "matches must be a list of objects"
    NOT_A_CANDIDATE = "{label} is not a label in CANDIDATES"
    BAD_EFFECT = "effect {effect!r} is not one of prevent, detect, contain, recover"


class ControlPickDrop(StrEnum):
    """Why code dropped a control the AI picked (stored in the scenario's controls.dropped)."""

    NO_SENTENCE = "names no sentence of this scenario"
    NOT_LISTED = "names no control of this scenario's list"
    BAD_EFFECT = "its effect is not prevent, detect, contain or recover"
    WRONG_TYPE = "the control's IT/OT type does not fit the scenario's systems"
    TWICE = "the control is already picked for another sentence of this scenario"
    TOO_MANY = "more than {most} controls on one sentence"


class ControlPickMessage(StrEnum):
    PICKED_REASON = "{effect}: {sentence}"  # a picked control's reason: how it helps, and the sentence it reduces
    SCENARIOS_NOT_A_LIST = "scenarios must be a list of objects, one per slot"


class TechniqueControlState(StrEnum):
    """What the pick gave each confirmed technique of a scenario (controls.technique_states)."""

    MATCHED = "matched"  # a control linked to one of its mitigations was picked
    NO_KNOWN_DEFENCE = "no_known_defence"  # ATT&CK records no mitigation for it
    NOT_PREPARED = "not_prepared"  # a mitigation of it has no link record yet, and none is linked to a control
    NO_LIBRARY_CONTROL = "no_library_control"  # its mitigations link to no library control
    TYPE_MISMATCH = "type_mismatch"  # the linked controls are of another IT/OT type than the scenario's systems
    NOT_OFFERED = "not_offered"  # its linked controls did not reach the shortlist: other links ranked higher
    NOT_PICKED = "not_picked"  # linked controls were offered and the AI picked none
