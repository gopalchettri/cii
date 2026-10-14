"""The real named groups a card shows beside its acting actor, as the API shows them (G230, owner 2026-10-14:
"Name the real group, also similar from the database as well. If not relevant from the database use near
possible"). Stored with the scenario (content.known_groups) when it was written with external intelligence;
none otherwise. A read never needs the intelligence."""

from typing import Any

from pydantic import BaseModel


class KnownGroupView(BaseModel):
    name: str
    attack_id: str | None  # ATT&CK's id (G0034)
    url: str | None  # its ATT&CK page
    kind: str  # nation_state, cybercriminal, ransomware, hacktivist or unknown
    who: str | None  # who it is, in the source's own words
    match: str  # used_this_technique, used_related_technique or nearest
    fits_actor: bool  # False: not of the acting actor's kind (ATT&CK records no insider group)
    technique: str  # the attack technique it is known for (T0858)
    technique_title: str
    through: str | None  # the campaign or malware it used it through; None: it used it itself
    how: str | None  # how it was used, in the source's own words
    cited: int | None  # the evidence number its technique is cited under on this card; None: not cited
    relevance: list[str]  # G232: targeted_country / targeted_region / targeted_sector; [] when none


def known_groups(content: dict[str, Any]) -> list[KnownGroupView]:
    return [
        KnownGroupView(
            name=item.get("name") or "",
            attack_id=item.get("group_id") or None,
            url=item.get("url") or None,
            kind=item.get("kind") or "unknown",
            who=item.get("who") or None,
            match=item.get("match") or "",
            fits_actor=bool(item.get("fits_actor", True)),
            technique=item.get("technique") or "",
            technique_title=item.get("technique_title") or "",
            through=item.get("through") or None,
            how=item.get("how") or None,
            cited=item.get("cited"),
            relevance=[str(level) for level in item.get("relevance") or ()],
        )
        for item in content.get("known_groups") or []
    ]
