"""G230 (owner 2026-10-14: "Name the real group, also similar from the database as well. If not relevant from
the database use near possible"): the real named groups a card shows beside its acting actor, picked in code:
of the actor's kind, behind the card's evidence first, then behind another technique the search found, then
the nearest by shared attacker goals; an insider's card gets the groups known for the attack, marked."""

import dataclasses
from typing import Any

import pytest

from app.core.constants import IntelKind, IntelSource, KnownGroupMatch, KnownGroups, ThreatGroupKind
from app.engine.external_intelligence.known_groups import fitting_kinds, pick_known_groups
from app.models.external_intelligence.evidence import IntelHit
from app.models.external_intelligence.known_groups import GroupMap
from tests.external_intelligence.evidence.test_evidence_finder import finder_of, one
from tests.external_intelligence.evidence_fakes import request_of, technique_doc

NS, CC, HK = ThreatGroupKind.NATION_STATE, ThreatGroupKind.CYBERCRIMINAL, ThreatGroupKind.HACKTIVIST
THIS, RELATED, NEAREST = (
    KnownGroupMatch.USED_THIS_TECHNIQUE,
    KnownGroupMatch.USED_RELATED_TECHNIQUE,
    KnownGroupMatch.NEAREST,
)


def _group(name: str, kind: str, through: str = "") -> dict[str, Any]:
    return {"name": name, "group_id": "G0001", "url": "https://attack.mitre.org/groups/G0001/", "kind": kind,
            "who": f"{name} is a group.", "through": through, "how": f"{name} did it."}  # fmt: skip


def _hit(ref: str, tactics: tuple[str, ...], *groups: dict[str, Any]) -> IntelHit:
    data = {"tactics": list(tactics), "groups": list(groups)}
    return IntelHit(
        ref, IntelKind.TECHNIQUE, f"Technique {ref}", "", "", IntelSource.ATTACK_ICS, "OT", data=data
    )


GROUPS = GroupMap.from_hits([
    _hit("T1", ("impact",), _group("Alpha", NS), _group("Crime", CC), _group("Delta", NS, through="Triton")),
    _hit("T2", ("impact",), _group("Bravo", NS), _group("Delta", NS)),
    _hit("T5", ("impact", "inhibit-response-function"), _group("Hackers", HK)),
    _hit("T6", ("discovery",), _group("Faraway", HK)),
])  # fmt: skip


def _names(picked: tuple) -> list[tuple[str, str, bool]]:
    return [(group.name, group.match, group.fits_actor) for group in picked]


@pytest.mark.parametrize(
    ("actor", "kinds"),
    [
        ("Nation-state/APT", {NS}),
        ("Nation-state group", {NS}),
        ("Cybercriminal", {CC, ThreatGroupKind.RANSOMWARE}),
        ("Organised cybercrime group", {CC, ThreatGroupKind.RANSOMWARE}),
        ("Ransomware affiliate", {ThreatGroupKind.RANSOMWARE, CC}),
        ("Hacktivist", {HK}),
        ("Malicious insider", set()),
        ("Negligent insider", set()),
        ("Third-party/Vendor", set()),
        ("Malicious user", set()),
        ("External attacker", None),
    ],
)
def test_which_group_kinds_fit_each_library_actor(actor: str, kinds: set | None) -> None:
    assert fitting_kinds(actor) == (None if kinds is None else frozenset(kinds))


def test_real_groups_of_the_actors_kind_come_first_then_similar_ones_each_once() -> None:
    picked = pick_known_groups("Nation-state/APT", ["T1"], ["T1", "T2"], GROUPS)
    assert _names(picked) == [("Alpha", THIS, True), ("Delta", THIS, True), ("Bravo", RELATED, True)]
    assert picked[1].through == "Triton" and picked[1].technique == "T1"  # how it came to be behind it
    assert "Crime" not in [group.name for group in picked]  # not a state group


def test_a_group_behind_more_of_the_evidence_comes_first() -> None:
    picked = pick_known_groups("Nation-state/APT", ["T1", "T2"], [], GROUPS)
    assert [group.name for group in picked] == ["Delta", "Alpha", "Bravo"]


def test_the_nearest_of_the_actors_kind_only_when_no_real_or_similar_one_is_known() -> None:
    picked = pick_known_groups("Hacktivist", ["T1"], ["T1", "T2"], GROUPS)
    assert _names(picked) == [("Hackers", NEAREST, True)]  # shares the goal "impact"; Faraway shares none
    assert picked[0].technique == "T5"


def test_an_insiders_card_gets_the_groups_known_for_the_attack_marked_as_not_its_kind() -> None:
    picked = pick_known_groups("Malicious insider", ["T1"], [], GROUPS)
    assert _names(picked) == [("Alpha", THIS, False), ("Crime", THIS, False), ("Delta", THIS, False)]


def test_an_external_attacker_takes_any_kind_and_a_kind_with_no_group_known_falls_back_marked() -> None:
    assert [group.fits_actor for group in pick_known_groups("External attacker", ["T1"], [], GROUPS)] == [
        True
    ] * 3
    picked = pick_known_groups("Ransomware affiliate", ["T6"], [], GROUPS)  # no ransomware group anywhere
    assert _names(picked) == [("Faraway", THIS, False)]


def test_at_most_three_and_none_without_evidence() -> None:
    many = GroupMap.from_hits([_hit("T9", ("impact",), *(_group(f"G{n}", NS) for n in range(6)))])
    assert len(pick_known_groups("Nation-state/APT", ["T9"], [], many)) == KnownGroups.SHOWN
    assert pick_known_groups("Nation-state/APT", [], [], GROUPS) == ()


def test_the_finder_returns_the_groups_behind_what_it_found_for_the_threats_actor() -> None:
    """End to end in the engine: the technique records' groups (the import's data.groups) and the request's
    actor; no AI call beyond the search's own."""
    docs = [technique_doc("T1", groups=[_group("Alpha", NS), _group("Crime", CC)], tactics=["impact"])]
    finder, _ = finder_of(docs)
    result, _ = one(finder, dataclasses.replace(request_of(), actor="Cybercriminal"))
    assert [group.name for group in result.groups] == ["Crime"]
    assert result.groups[0].as_doc()["how"] == "Crime did it."
