"""Who did it (G230, owner 2026-10-14: "Name the real group"): the named threat groups behind each ATT&CK
technique, as the bundle records them. A group used a technique directly, in a campaign attributed to it
(2015 Ukraine Electric Power Attack -> Sandworm Team), or through software it uses (Triton -> TEMP.Veles):
for OT techniques ATT&CK mostly names the software, not the group, so all three links count.

Each group keeps its ATT&CK id, its page, who it is (the first sentence of its own description) and its kind,
read from that description, and (G232) the places and sectors that description says it attacked; each link
keeps how the group, campaign or software used the technique. Every
text is cleaned like every other text of the bundle: a group whose description is unsafe keeps its name, with
no description and kind unknown."""

import re
from typing import Any

from app.core.constants import AttackReading, KnownGroups, SourceHosts, ThreatGroupKind
from app.engine.external_intelligence.place_words import targets_of
from app.services.external_intelligence.sources.text_guard import SourceTextGuard, UnsafeSourceText

_STATE = re.compile(
    r"state[- ](?:sponsored|backed)|nation[- ]state|espionage|\b(?:GRU|FSB|SVR|MSS|MOIS|IRGC|RGB|PLA)\b|"
    r"(?:\b(?:attributed|linked|tied|nexus) to|\bassociated with|on behalf of|sponsored by|backed by)\b"
    r"[^.]{0,80}?\b(?:government|military|intelligence|ministry|army|directorate)\b",
    re.I,
)
_CRIMINAL = re.compile(
    r"financially[- ]motivated|cyber ?crim|\bcriminal|initial access broker|crypto(?:currency)?[- ]?mining|"
    r"cryptojack|botnet|business email compromise",
    re.I,
)
#: Where a group comes FROM (never whom it targeted: "targeted victims in Russia" names no origin): the
#: countries whose state groups ATT&CK records, in its own wordings ("China-based", "suspected Iranian threat
#: group", "with Chinese origins", "attributed to actors operating out of China").
_NATION = r"(?:Chin(?:a|ese)|People's Republic of China|PRC|Russia(?:n)?|Iran(?:ian)?|North Korea(?:n)?|DPRK|"
_NATION += r"Vietnam(?:ese)?|Pakistan(?:i)?|India(?:n)?)"
_STATE_ORIGIN = re.compile(
    rf"\b{_NATION}[- ](?:based|linked|related|nexus|aligned)\b|\b{_NATION} (?:cyber )?(?:threat )?"
    rf"(?:group|actor|nexus|origins?)\b|\b(?:attributed to|linked to|associated with|nexus to|"
    rf"operat\w* (?:out of|from))\b[^.]{{0,40}}?\b{_NATION}\b",
    re.I,
)
#: A group's kind, the first rule that matches: in the first sentence of its description (who it is: origin
#: counts there), else anywhere in it (origin does not: a later sentence names whom it targeted). None:
#: unknown. Crime before origin: "a Russia-based financially motivated group" is criminal.
_WHO_RULES = (
    (ThreatGroupKind.HACKTIVIST, re.compile(r"\bhacktivis", re.I)),
    (ThreatGroupKind.NATION_STATE, _STATE),
    (ThreatGroupKind.RANSOMWARE, re.compile(r"\bransomware\b", re.I)),
    (ThreatGroupKind.CYBERCRIMINAL, _CRIMINAL),
    (ThreatGroupKind.NATION_STATE, _STATE_ORIGIN),
)
_GROUP_ID = re.compile(r"G\d{4}")
_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


def group_kind(description: str) -> ThreatGroupKind:
    who = _SENTENCE_END.split(description, maxsplit=1)[0]
    for text, rules in ((who, _WHO_RULES), (description, _WHO_RULES[:4])):
        kind = next((kind for kind, rule in rules if rule.search(text)), None)
        if kind is not None:
            return kind
    return ThreatGroupKind.UNKNOWN


class AttackGroups:
    """The groups of one bundle and every link from a technique to them, filled while the bundle is indexed.
    `names`: the bundle index's stix id -> (name, actor kind), shared, complete before any link is read."""

    def __init__(self, guard: SourceTextGuard, names: dict[str, tuple[str, str]]) -> None:
        self._guard, self._names = guard, names
        self._profiles: dict[str, dict[str, Any]] = {}  # stix id -> name, id, url, kind, who, places, sectors
        self._attributed: dict[str, list[str]] = {}  # campaign stix id -> its groups
        self._users_of_software: dict[str, list[str]] = {}  # software stix id -> the groups that use it
        self._users: dict[str, list[tuple[str, str]]] = {}  # technique stix id -> (user stix id, how)

    def add_group(self, obj: dict[str, Any], name: str, ref: dict[str, Any]) -> None:
        group_id = ref.get("external_id") if _GROUP_ID.fullmatch(str(ref.get("external_id"))) else ""
        page = SourceHosts.ATTACK_GROUP_PAGE.format(group_id=group_id) if group_id else ""
        url = self._guard.clean_link(ref.get("url"), SourceHosts.ATTACK_PAGES) or page
        description = self._description(obj)
        who = _SENTENCE_END.split(description, maxsplit=1)[0][: KnownGroups.WHO_CHARS] if description else ""
        places, sectors = targets_of(description.replace(name, " "))  # its own name is never a target
        self._profiles[obj["id"]] = {
            "name": name,
            "group_id": str(group_id),
            "url": url,
            "kind": group_kind(description),
            "who": who,
            "places": places,
            "sectors": sectors,
        }

    def attribute(self, campaign: str, group: str) -> None:
        self._attributed.setdefault(campaign, []).append(group)

    def used(self, user: str, user_kind: str, target: Any, how: str) -> None:
        """`user` (a group, campaign or software) uses `target`: a technique, or software a group uses."""
        if not isinstance(target, str):
            return
        if self._names.get(target, ("", ""))[1] == "software":
            if user_kind == "group":
                self._users_of_software.setdefault(target, []).append(user)
        elif target not in self._names:  # a technique (techniques are not named actors)
            self._users.setdefault(target, []).append((user, how))

    def groups_of(self, technique: Any) -> list[dict[str, Any]]:
        """The groups behind a technique, each once (by its direct use when it has one), with the campaign or
        software it came through ("" for a direct user) and how it was used; at most PER_TECHNIQUE. G232: the
        groups that attacked a known place (PLACE_WORDS) are kept first, then direct users, then by name: an
        alphabetical cap dropped the Gulf groups behind common techniques (live 2026-10-14)."""
        links = []
        for user, how in self._users.get(technique, []) if isinstance(technique, str) else []:
            user_name, kind = self._names.get(user, ("", ""))
            through = "" if kind == "group" else user_name
            for group in self._behind(user, kind):
                if group in self._profiles:
                    links.append(self._profiles[group] | {"through": through, "how": how})
        links.sort(key=lambda link: (link["through"] != "", link["name"].casefold(), link["through"]))
        kept: dict[str, dict[str, Any]] = {}
        for link in links:  # the first link of each group wins: a direct use before one through software
            kept.setdefault(link["name"], link)
        nearest = sorted(kept.values(), key=lambda link: not link.get("places"))  # stable: keeps the order
        return nearest[: KnownGroups.PER_TECHNIQUE]

    def _behind(self, user: str, kind: str) -> list[str]:
        if kind == "group":
            return [user]
        if kind == "campaign":
            return self._attributed.get(user, [])
        return self._users_of_software.get(user, []) if kind == "software" else []

    def _description(self, obj: dict[str, Any]) -> str:
        try:
            plain = _CITATION.sub("", str(obj.get("description") or ""))
            return self._guard.clean_sentences(plain, AttackReading.TEXT_LIMIT)
        except UnsafeSourceText as unsafe:
            self._guard.quarantine("", obj, unsafe.reason)  # nothing clean left: kept without a description
            return ""
