"""G232 (owner 2026-10-14: threats, groups and sources relevant to the UAE; no AI call added): the places and
sectors a group attacked (never where it comes from), groups ranked country, region, sector; sources labelled
country, regional or global; a claim of a local incident needs a local source; only a "it happened before"
sentence needs a named attacker; planning prefers a nearer threat only after coverage; the country reaches
planning and the story writer as a fact, and only while external intelligence is on."""

import dataclasses
import json
from typing import Any

import pytest
from pydantic import ValidationError

from app.core.config import Settings, get_settings
from app.core.constants import (
    AiTask,
    Collection,
    EvidenceBlock,
    EvidenceScope,
    FindingCode,
    GroupRelevance,
    StrideCategory,
    ThreatGroupKind,
    WriterStyle,
)
from app.engine.external_intelligence.known_groups import pick_known_groups
from app.engine.external_intelligence.place_words import sectors_in, targets_of
from app.engine.external_intelligence.story.evidence_story_prompts import evidence_block
from app.engine.external_intelligence.threat_relevance import threat_relevance
from app.engine.scenarios.attack_paths.path_grouping import path_on
from app.engine.scenarios.attack_paths.path_ranking import rank_paths
from app.engine.scenarios.attack_paths.path_selector import AttackPathSelector
from app.engine.scenarios.finding.asset_landscape import describe_asset_for_ai
from app.engine.scenarios.writing.evidence_checks import evidence_findings, supports
from app.models.external_intelligence.known_groups import GroupMap, Nearness
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.worker import jobs
from app.worker.tasks import scenarios as scenario_tasks
from tests.external_intelligence.evidence.test_evidence_finder import finder_of, one
from tests.external_intelligence.evidence.test_known_groups import _hit
from tests.external_intelligence.evidence_fakes import request_of, technique_doc
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _DRAFT, _story_brief
from tests.planner_samples import ADMIN_ABUSE, CONTEXT, LOG_WIPE, finder, planned, planner_chat
from tests.test_attack_paths import _queued_run, _stored_run, _threats_task, sent  # noqa: F401 - fixture

UAE = "United Arab Emirates"
NEAR = Nearness(UAE, frozenset({"aviation"}))
NS = ThreatGroupKind.NATION_STATE


def _group(name: str, places: tuple[str, ...] = (), sectors: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"name": name, "group_id": "", "url": "", "kind": NS, "who": "", "through": "", "how": "",
            "places": list(places), "sectors": list(sectors)}  # fmt: skip


@pytest.mark.parametrize(
    ("description", "places", "sectors"),
    [
        ("OilRig is a suspected Iranian threat group that has targeted Middle Eastern victims, including "
         "financial and energy organisations.", ["Middle East"], ["energy", "finance"]),
        ("APT33 has targeted organizations in Saudi Arabia with an interest in aviation.", ["Saudi Arabia"],
         ["aviation"]),
        ("Stealth Falcon has conducted spyware attacks against Emirati journalists.", [UAE], []),
        # where a group comes from is never whom it attacked
        ("Group X is a UAE-based threat group that targeted banks in Kuwait.", ["Kuwait"], ["finance"]),
        ("Sandworm Team has been attributed to Russia's GRU military unit 74455.", [], []),
        # what a group IS is where it comes from (ATT&CK's own wordings, live 2026-10-14)
        ("BlackOasis is a Middle Eastern threat group that is believed to be a customer of Gamma Group.",
         [], []),
        ("Group Y is an Emirati threat actor that has targeted energy firms in Oman.", ["Oman"], ["energy"]),
        ("Agrius is an Iranian threat actor notable for wiper operations in the Middle East.",
         ["Middle East"], []),
        ("Stealth Falcon is a threat group that has conducted attacks against Emirati journalists.",
         [UAE], []),
        # ATT&CK's other uses of sector words are not sectors
        ("It inspects network traffic on industrial control systems and social media.", [], []),
    ],
)  # fmt: skip
def test_the_places_and_sectors_a_group_attacked(description: str, places: list, sectors: list) -> None:
    assert targets_of(description) == (places, sectors)


def test_groups_of_a_step_are_ranked_country_then_region_then_sector_and_say_why() -> None:
    groups = GroupMap.from_hits([_hit(
        "T1", ("impact",), _group("Alpha"), _group("Gulfwatch", ("Gulf",)), _group("Falcon", (UAE,)),
        _group("Skyline", (), ("aviation",)), _group("Both", ("Qatar",), ("aviation",)),
    )])  # fmt: skip
    picked = pick_known_groups("Nation-state/APT", ["T1"], [], groups, NEAR)
    assert [group.name for group in picked] == ["Falcon", "Both", "Gulfwatch", "Skyline", "Alpha"]
    assert picked[0].relevance == (GroupRelevance.TARGETED_COUNTRY,)
    assert picked[1].relevance == (GroupRelevance.TARGETED_REGION, GroupRelevance.TARGETED_SECTOR)
    plain = pick_known_groups("Nation-state/APT", ["T1"], [], groups)  # no country: as G230, by name
    assert [group.name for group in plain][:3] == ["Alpha", "Both", "Falcon"]


def test_a_source_is_labelled_country_regional_or_global_by_the_groups_behind_it() -> None:
    assert NEAR.scope([]) == EvidenceScope.GLOBAL
    uses = GroupMap.from_hits([_hit("T1", (), _group("A", ("Oman",))), _hit("T2", (), _group("B", (UAE,)))])
    assert NEAR.scope(uses.by_technique["T1"]) == EvidenceScope.REGIONAL
    assert NEAR.scope(uses.by_technique["T2"]) == EvidenceScope.COUNTRY


def test_only_a_sentence_saying_something_happened_needs_the_named_attacker() -> None:
    entry = {"facts": ["Gamaredon Group, a threat group, has used this technique."]}
    assert supports("An attacker could flood the wireless links of the signal controllers [1].", entry)
    assert supports("Gamaredon Group has used this technique for impact [1].", entry)
    assert not supports("Attackers have done this before [1].", entry)
    assert not supports("The C0027 campaign used similar access techniques [1].", entry)


def _findings_of(statement: str, scope: EvidenceScope) -> set[str]:
    brief = _story_brief(dataclasses.replace(TECHNIQUE, scope=scope))
    draft = dataclasses.replace(_DRAFT, statement=statement)
    return {finding.code for finding in evidence_findings(draft, brief)}


def test_a_local_incident_needs_a_local_source() -> None:
    claim = "Rogue firmware updates have disabled substation devices in the UAE before [1]."
    assert FindingCode.COUNTRY_CLAIM_UNSUPPORTED in _findings_of(claim, EvidenceScope.REGIONAL)
    assert FindingCode.COUNTRY_CLAIM_UNSUPPORTED not in _findings_of(claim, EvidenceScope.COUNTRY)
    where = "A rogue firmware update could disable Dubai's substation devices [1]."  # where, not an incident
    assert FindingCode.COUNTRY_CLAIM_UNSUPPORTED not in _findings_of(where, EvidenceScope.GLOBAL)


def test_planning_reads_each_threats_nearness_by_keywords_with_its_groups() -> None:
    docs = [
        technique_doc("T1566", text="phishing emails with malicious links", tactics=["initial-access"],
                      groups=[_group("Falcon", (UAE,))]),
        technique_doc("T1486", text="ransomware encrypts files for impact", tactics=["impact"],
                      groups=[_group("Gulfwatch", ("Gulf",))]),
        technique_doc("T1046", text="network service discovery scanning", tactics=["discovery"]),
    ]  # fmt: skip
    corpus = CorpusBuilder().build_corpus(docs)
    threats = [planned("lib:1", "Credential phishing"), planned("lib:2", "Ransomware extortion"),
               planned("lib:3", "Service scanning")]  # fmt: skip
    found = threat_relevance(corpus, threats, NEAR)
    assert (found["lib:1"]["scope"], found["lib:1"]["groups"]) == ("country", ["Falcon"])
    assert (found["lib:2"]["scope"], found["lib:2"]["groups"]) == ("regional", ["Gulfwatch"])
    assert found["lib:3"]["scope"] == "global" and found["lib:3"]["groups"] == []
    assert threat_relevance(corpus, threats, Nearness()) == {}  # no country: nothing to rank by


def test_a_nearer_threat_only_breaks_a_tie_and_never_beats_coverage() -> None:
    def path(key: str, systems: tuple[int, ...], scope: str | None) -> Any:
        near = {"scope": scope, "techniques": [], "groups": []} if scope else None
        threat = planned(key, key, systems, categories=(StrideCategory.TAMPERING,), country_relevance=near)
        return path_on(threat, systems)

    tie = [path("lib:1", (321,), None), path("lib:2", (321,), "country")]
    assert [p.steps[0].key for p, _ in rank_paths(tie)][0] == "lib:2"
    wider = [path("lib:1", (321, 322), None), path("lib:2", (321,), "country")]
    assert [p.steps[0].key for p, _ in rank_paths(wider)][0] == "lib:1"  # more systems covered first


def test_the_country_reaches_planning_and_the_story_writer_only_when_intelligence_is_on() -> None:
    assert '"country": "United Arab Emirates"' in describe_asset_for_ai(CONTEXT, 20_000, UAE).text
    assert '"country"' not in describe_asset_for_ai(CONTEXT, 20_000).text
    assert _story_brief(TECHNIQUE).asset["country"] == get_settings().context_country
    assert "country" not in _story_brief(TECHNIQUE, style=WriterStyle.ORIGINAL).asset


def test_the_country_setting_takes_its_short_name_and_refuses_one_it_does_not_know() -> None:
    values = get_settings().model_dump()
    assert Settings(_env_file=None, **(values | {"threat_context_country": "UAE"})).context_country == UAE
    with pytest.raises(ValidationError, match="THREAT_CONTEXT_COUNTRY"):
        Settings(_env_file=None, **(values | {"threat_context_country": "Atlantis"}))


def test_the_asset_sectors_come_from_its_sector_facts() -> None:
    assert sectors_in("Transportation · Aviation · Airport operations") == ["aviation", "transportation"]


def test_the_finder_labels_each_source_it_returns() -> None:
    docs = [technique_doc("T1", groups=[_group("Falcon", (UAE,))], tactics=["impact"])]
    finder, _ = finder_of(docs)
    result, _ = one(finder, dataclasses.replace(request_of(), actor="Nation-state/APT", near=NEAR))
    assert [item.scope for item in result.evidence] == [EvidenceScope.COUNTRY]
    assert result.groups[0].relevance == (GroupRelevance.TARGETED_COUNTRY,)


def test_a_threat_takes_the_nearest_scope_of_the_techniques_it_reads_like() -> None:
    docs = [
        technique_doc(
            "T1566", text="phishing emails", tactics=["initial-access"], groups=[_group("F", (UAE,))]
        ),
        technique_doc("T1598", text="phishing for information", tactics=["reconnaissance"]),
    ]
    found = threat_relevance(CorpusBuilder().build_corpus(docs), [planned("lib:1", "Phishing")], NEAR)
    assert found["lib:1"]["scope"] == "country" and sorted(found["lib:1"]["techniques"]) == ["T1566", "T1598"]


def test_the_writer_reads_each_sources_scope() -> None:
    block = evidence_block(_story_brief(dataclasses.replace(TECHNIQUE, scope=EvidenceScope.REGIONAL)))
    body = json.loads(block.split(EvidenceBlock.BEGIN + "\n", 1)[1].rsplit("\n" + EvidenceBlock.END, 1)[0])
    assert body["evidence"][0]["scope"] == "regional"


class _IntelOn:
    """The planning job's intelligence access with the switch on: every threat near the country."""

    def is_on(self) -> bool:
        return True

    def plan_intel(self, threats: list, context: Any) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
        nearness = {"scope": "country", "techniques": ["T1"], "groups": ["Falcon"]}
        near = {threat.key: nearness for threat in threats}
        return near, {"intel_snapshot_id": "snap-9", "intel_sources": {}}


def test_planning_with_intelligence_on_reads_the_country_and_keeps_each_threats_nearness(
    monkeypatch: pytest.MonkeyPatch,
    sent: list[tuple[Any, ...]],  # noqa: F811 - the imported fixture
) -> None:
    chat = planner_chat({LOG_WIPE.name: ["SYS1"], ADMIN_ABUSE.name: ["SYS2"]})
    monkeypatch.setattr(scenario_tasks, "get_threat_finder", lambda: finder(chat))
    monkeypatch.setattr(scenario_tasks, "get_attack_path_selector", lambda: AttackPathSelector(target=0))
    monkeypatch.setattr(scenario_tasks, "get_intel_access", _IntelOn)
    record_id = _queued_run()
    jobs.run_leased_job(_threats_task(), Collection.SESSIONS, record_id, 1, scenario_tasks.plan_run)
    threats = _stored_run(record_id)["plan"]["threats"]
    assert threats and all(threat["country_relevance"]["groups"] == ["Falcon"] for threat in threats)
    # G238: the plan records the snapshot it ranked with, from the same read
    assert _stored_run(record_id)["plan"]["made_with"]["intel_snapshot_id"] == "snap-9"
    assert all(f'"country": "{UAE}"' in user for user in chat.asked(AiTask.RELEVANCE_GATE))
