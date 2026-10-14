"""The named threat groups behind the evidence index's techniques, and those a card shows (G230, owner
2026-10-14: "Name the real group, also similar from the database as well. If not relevant from the database
use near possible"). Read from each technique record's `data.groups` (the ATT&CK import), once per index."""

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from app.core.constants import (
    COUNTRY_REGIONS,
    EvidenceScope,
    GroupRelevance,
    IntelKind,
    KnownGroupMatch,
    ThreatGroupKind,
)
from app.models.external_intelligence.evidence import IntelHit


@dataclass(frozen=True)
class GroupUse:
    """One named group behind one technique: who it is, and how it (or its campaign or software) used it."""

    name: str
    group_id: str  # ATT&CK's id (G0034); "" when the source gave none
    url: str
    kind: ThreatGroupKind
    who: str  # the first sentence of the group's own description
    through: str  # the campaign or software it used the technique through; "" when it used it itself
    how: str  # how it was used, in the source's words
    technique: str  # the technique's id (T0858)
    technique_title: str
    places: tuple[str, ...] = ()  # G232: the places its description says it attacked
    sectors: tuple[str, ...] = ()  # G232: the sectors it attacked


@dataclass(frozen=True)
class KnownGroup(GroupUse):
    """A group shown on a card, and why."""

    match: KnownGroupMatch = KnownGroupMatch.USED_THIS_TECHNIQUE
    fits_actor: bool = True  # False: not of the acting actor's kind (an insider's card: no insider group)
    relevance: tuple[GroupRelevance, ...] = ()  # G232: it attacked this country, its region, this sector

    def as_doc(self) -> dict[str, Any]:
        return {
            key: list(value) if isinstance(value, tuple) else value for key, value in asdict(self).items()
        }


@dataclass(frozen=True)
class Nearness:
    """What makes a group near this asset (G232): the deployment's country (THREAT_CONTEXT_COUNTRY) and the
    asset's sectors. Empty: nothing is near (intelligence off, a test about something else)."""

    country: str = ""
    sectors: frozenset[str] = frozenset()

    def of(self, use: GroupUse) -> tuple[GroupRelevance, ...]:
        region = COUNTRY_REGIONS.get(self.country, frozenset())
        found = (
            (GroupRelevance.TARGETED_COUNTRY, bool(self.country) and self.country in use.places),
            (GroupRelevance.TARGETED_REGION, bool(region & set(use.places))),
            (GroupRelevance.TARGETED_SECTOR, bool(self.sectors & set(use.sectors))),
        )
        return tuple(relevance for relevance, yes in found if yes)

    def scope(self, uses: Iterable[GroupUse]) -> EvidenceScope:
        """What a technique tells about place: a group behind it attacked the country, else its region, else
        none did (global)."""
        found = {relevance for use in uses for relevance in self.of(use)}
        if GroupRelevance.TARGETED_COUNTRY in found:
            return EvidenceScope.COUNTRY
        return EvidenceScope.REGIONAL if GroupRelevance.TARGETED_REGION in found else EvidenceScope.GLOBAL


@dataclass(frozen=True)
class GroupMap:
    """Every technique's groups (direct users first, as imported), every technique's attacker goals
    (tactics), and every group's goals over all the techniques it is behind."""

    by_technique: dict[str, tuple[GroupUse, ...]] = field(default_factory=dict)
    tactics: dict[str, frozenset[str]] = field(default_factory=dict)
    group_tactics: dict[str, frozenset[str]] = field(default_factory=dict)

    @classmethod
    def from_hits(cls, hits: Iterable[IntelHit]) -> "GroupMap":
        by_technique: dict[str, tuple[GroupUse, ...]] = {}
        tactics: dict[str, frozenset[str]] = {}
        goals: dict[str, set[str]] = {}
        for hit in hits:
            if hit.kind != IntelKind.TECHNIQUE:
                continue
            tactics[hit.external_id] = frozenset(hit.data.get("tactics") or ())
            uses = tuple(_use(item, hit) for item in hit.data.get("groups") or () if isinstance(item, dict))
            by_technique[hit.external_id] = uses
            for use in uses:
                goals.setdefault(use.name, set()).update(tactics[hit.external_id])
        return cls(by_technique, tactics, {name: frozenset(found) for name, found in goals.items()})


def _use(item: dict[str, Any], hit: IntelHit) -> GroupUse:
    kind = str(item.get("kind"))
    return GroupUse(
        name=str(item.get("name") or ""),
        group_id=str(item.get("group_id") or ""),
        url=str(item.get("url") or ""),
        kind=ThreatGroupKind(kind) if kind in ThreatGroupKind else ThreatGroupKind.UNKNOWN,
        who=str(item.get("who") or ""),
        through=str(item.get("through") or ""),
        how=str(item.get("how") or ""),
        technique=hit.external_id,
        technique_title=hit.title,
        places=tuple(str(place) for place in item.get("places") or ()),
        sectors=tuple(str(sector) for sector in item.get("sectors") or ()),
    )
