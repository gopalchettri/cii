"""Threats as the same-attack check shows them to the AI (v1 paths._slotted and _shown):
slots THR1, THR2 ..., names without library codes, systems by alias."""

from typing import Any

from app.core.constants import ThreatFinding
from app.engine.shared.names import threat_name_without_code
from app.models.threats import PlannedThreat

#: The "system" a threat that names none acts on: the asset itself (supporting system ids are positive).
_THE_ASSET = 0


def threats_by_code(threats: list[PlannedThreat]) -> dict[str, PlannedThreat]:
    """The threats by slot, those sharing systems next to each other so they share a batch."""
    ordered = sorted(threats, key=lambda threat: (threat.systems or (_THE_ASSET,), threat.key))
    return {
        f"{ThreatFinding.THREAT_SLOT}{position}": threat for position, threat in enumerate(ordered, start=1)
    }


def threat_as_ai_sees_it(slot: str, threat: PlannedThreat, aliases: dict[int, str]) -> dict[str, Any]:
    """No attacker: attackers are chosen after this check (G110), so none is known yet (review 2026-10-11:
    every item carried an empty "attacker")."""
    return {
        "slot": slot,
        "category": threat.categories[0],
        "threat_type": threat_name_without_code(threat.type_name),
        "threat": threat_name_without_code(threat.name),
        "systems": [aliases[system] for system in threat.systems if system in aliases],
    }


def systems_of_threat(threat: PlannedThreat) -> set[int]:
    """The systems a threat involves; the asset itself when it names none."""
    return set(threat.systems or (_THE_ASSET,))


def code_to_name_map(slots: dict[str, PlannedThreat], system_names: dict[str, str]) -> dict[str, str]:
    """Every code handed to the AI and what it stands for, to turn a code it still wrote back into a name."""
    return {**system_names, **{slot: threat_name_without_code(threat.name) for slot, threat in slots.items()}}
