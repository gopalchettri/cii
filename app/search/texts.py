"""The text each library row is searched by: v1's texts, so v1 and v2 rank alike."""

from app.models.library import LibraryActor, LibraryControl, LibraryThreat, LibraryThreatType


def describe_threat(threat: LibraryThreat) -> str:
    # v1's threat planner searches "ThreatTypeName: ThreatName" (landscape.shortlists): the type adds the
    # family words ("Malware/Ransomware", "Social engineering") that a bare threat name often lacks.
    return f"{threat.type_name}: {threat.name}"


def describe_control(control: LibraryControl) -> str:
    return f"{control.name}: {control.description or ''}"  # v1: "ControlName: ControlDescription"


def describe_actor(actor: LibraryActor) -> str:
    return actor.name


def describe_threat_type(threat_type: LibraryThreatType) -> str:
    # v1 matches a proposed threat type against the type names (grounding.py: group "threat_type").
    return threat_type.name
