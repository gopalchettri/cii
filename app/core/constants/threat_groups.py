"""Named threat groups on a card (G230, owner 2026-10-14: "Name the real group, also similar from the database
as well. If not relevant from the database use near possible"). The ATT&CK import keeps each group behind a
technique; a card written with external intelligence shows a few of them beside its acting actor (a type of
attacker, never a named group: G122), never in the story."""

from enum import StrEnum
from typing import Final


class ThreatGroupKind(StrEnum):
    """What kind of group ATT&CK's own description says it is (read at import, first rule that matches)."""

    NATION_STATE = "nation_state"
    HACKTIVIST = "hacktivist"
    RANSOMWARE = "ransomware"
    CYBERCRIMINAL = "cybercriminal"
    UNKNOWN = "unknown"


class KnownGroupMatch(StrEnum):
    """Why a group is on a card, best first."""

    USED_THIS_TECHNIQUE = "used_this_technique"  # used a technique of the card's own evidence
    USED_RELATED_TECHNIQUE = "used_related_technique"  # used another technique the evidence search found
    NEAREST = "nearest"  # neither: of the actor's kind, it used a technique with the same attacker goal


class KnownGroups:
    SHOWN: Final = 3  # groups on one card
    #: G235: groups kept with a threat's evidence, so the card can show those behind what its story cites
    #: (picked when the scenario is saved, not before it is written).
    CANDIDATES: Final = 9
    PER_TECHNIQUE: Final = 10  # groups the import keeps per technique: direct users first, then by name
    WHO_CHARS: Final = 200  # the first sentence of a group's own description
    TECHNIQUES_PER_THREAT: Final = 3  # G232: the techniques a planned threat reads most like (keywords only)


class GroupRelevance(StrEnum):
    """Why a group is near this asset (G232), shown beside it; the first three order the groups of a step."""

    TARGETED_COUNTRY = "targeted_country"  # its description says it attacked the deployment's country
    TARGETED_REGION = "targeted_region"  # it attacked that country's region (the Gulf, the Middle East)
    TARGETED_SECTOR = "targeted_sector"  # it attacked the asset's sector


class EvidenceScope(StrEnum):
    """What a source tells about place (G232): groups behind it attacked the country, or its region, or none
    is known to have (global). Never proof that the asset or its organisation was attacked."""

    COUNTRY = "country"
    REGIONAL = "regional"
    GLOBAL = "global"


#: How near a source or a threat is (G232): the path ranking prefers the higher, after coverage.
SCOPE_RANK: Final[dict[str, int]] = {"country": 2, "regional": 1, "global": 0}

#: A place a group's description says it attacked (G232) -> the place it names: the countries a deployment
#: may set in THREAT_CONTEXT_COUNTRY and their regions. Matched as whole words, any case.
PLACE_WORDS: Final[dict[str, str]] = {
    "united arab emirates": "United Arab Emirates", "uae": "United Arab Emirates",
    "u.a.e.": "United Arab Emirates", "emirati": "United Arab Emirates", "emirates": "United Arab Emirates",
    "abu dhabi": "United Arab Emirates", "dubai": "United Arab Emirates", "sharjah": "United Arab Emirates",
    "ajman": "United Arab Emirates", "fujairah": "United Arab Emirates",
    "ras al khaimah": "United Arab Emirates", "umm al quwain": "United Arab Emirates",
    "saudi arabia": "Saudi Arabia", "saudi": "Saudi Arabia", "qatar": "Qatar", "qatari": "Qatar",
    "kuwait": "Kuwait", "kuwaiti": "Kuwait", "bahrain": "Bahrain", "bahraini": "Bahrain", "oman": "Oman",
    "omani": "Oman", "middle east": "Middle East", "middle eastern": "Middle East", "mena": "Middle East",
    "gulf": "Gulf", "gcc": "Gulf", "arabian peninsula": "Gulf",
}  # fmt: skip
#: The countries THREAT_CONTEXT_COUNTRY may name, each with the places that are its region.
COUNTRY_REGIONS: Final[dict[str, frozenset[str]]] = {
    "United Arab Emirates": frozenset(
        {"Saudi Arabia", "Qatar", "Kuwait", "Bahrain", "Oman", "Middle East", "Gulf"}
    ),
}
#: A word naming a sector -> the sector (G232): read from whom a group attacked and from the asset's sector,
#: sub-sector and critical service, then compared. Words ATT&CK uses for other things ("port", "power",
#: "network traffic", "industrial control", "social media") are left out.
SECTOR_WORDS: Final[dict[str, str]] = {
    "aviation": "aviation", "airline": "aviation", "airlines": "aviation", "airport": "aviation",
    "airports": "aviation", "aerospace": "aviation", "aircraft": "aviation",
    "transportation": "transportation", "transport": "transportation",
    "logistics": "transportation", "railway": "transportation", "railways": "transportation",
    "maritime": "maritime", "shipping": "maritime",
    "energy": "energy", "oil": "energy", "gas": "energy", "petrochemical": "energy", "electricity": "energy",
    "electric": "energy", "nuclear": "energy", "utilities": "utilities", "utility": "utilities",
    "water": "utilities",
    "government": "government", "governmental": "government", "ministries": "government",
    "defense": "defense", "defence": "defense", "military": "defense",
    "finance": "finance", "financial": "finance", "banking": "finance", "banks": "finance",
    "telecommunications": "telecommunications", "telecommunication": "telecommunications",
    "telecom": "telecommunications",
    "healthcare": "healthcare", "hospitals": "healthcare", "pharmaceutical": "healthcare",
    "education": "education", "universities": "education", "academic": "education",
    "manufacturing": "manufacturing", "chemical": "manufacturing",
    "hospitality": "hospitality", "hotels": "hospitality", "retail": "retail",
    "construction": "construction",
}  # fmt: skip
