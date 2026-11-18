"""tsg_attack and tsg_control_links against the real MongoDB: a source's graph replaced whole (never emptied
half way), the three reads the ATT&CK check makes, the mitigations the linking judges, and the stored links."""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.core.constants import (
    AttackLink,
    AttackObjectType,
    AttackRecord,
    Collection,
    ControlEffect,
    ControlLinks,
    IntelLimits,
    IntelSource,
)
from app.core.database import get_mongodb
from app.crud.attack import (
    AttackRepository,
    ControlLinkRepository,
    attack_doc_id,
    get_attack_repository,
    get_control_link_repository,
)
from app.crud.base import SCHEMA_VERSION_FIELD

ICS, ENTERPRISE = IntelSource.ATTACK_ICS, IntelSource.ATTACK_ENTERPRISE
SANDWORM, VALID_ICS, VALID_IT = "intrusion-set--sandworm", "attack-pattern--valid-ics", "attack-pattern--valid-it"
MFA_ICS, MFA_IT, NOT_EFFECTIVE, UNUSED = "course-of-action--mfa-ics", "course-of-action--mfa-it", "coa--none", "coa--x"
MFA = "Multi-factor Authentication"
NOW = datetime(2026, 11, 17, 2, 0, tzinfo=UTC)


def _object(source: str, stix_id: str, kind: str, attack_id: str, name: str, *aliases: str) -> dict[str, Any]:
    return {
        "_id": attack_doc_id(source, stix_id),
        "record": AttackRecord.OBJECT,
        "stix_id": stix_id,
        "type": kind,
        "attack_id": attack_id,
        "name": name,
        "name_keys": [text.casefold() for text in (name, *aliases)],
        "aliases": list(aliases),
        "description": f"{name} described.",
        "url": f"https://attack.mitre.org/{attack_id}",
    }


def _link(source: str, kind: str, source_ref: str, target_ref: str, description: str = "") -> dict[str, Any]:
    return {
        "_id": attack_doc_id(source, f"relationship--{kind}-{source_ref}-{target_ref}"),
        "record": AttackRecord.RELATIONSHIP,
        "type": kind,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": description,
        "citations": [{"name": "Report", "url": "https://example.test/report"}] if description else [],
    }


def ics_graph() -> list[dict[str, Any]]:
    """Sandworm uses Valid Accounts (T0859); MFA (M0932) and a "not a mitigation" entry mitigate it; one
    mitigation no technique names."""
    return [
        _object(ICS, SANDWORM, AttackObjectType.GROUP, "G0034", "Sandworm Team", "ELECTRUM", "Voodoo Bear"),
        _object(ICS, VALID_ICS, AttackObjectType.TECHNIQUE, "T0859", "Valid Accounts"),
        _object(ICS, MFA_ICS, AttackObjectType.MITIGATION, "M0932", MFA),
        _object(ICS, NOT_EFFECTIVE, AttackObjectType.MITIGATION, "M0816", "Mitigation Limited or Not Effective"),
        _object(ICS, UNUSED, AttackObjectType.MITIGATION, "M0999", "Unnamed By Any Technique"),
        _link(ICS, AttackLink.USES, SANDWORM, VALID_ICS, "Sandworm Team used valid accounts in the 2015 attack."),
        _link(ICS, AttackLink.MITIGATES, MFA_ICS, VALID_ICS),
        _link(ICS, AttackLink.MITIGATES, NOT_EFFECTIVE, VALID_ICS),
    ]


def enterprise_graph() -> list[dict[str, Any]]:
    """The same group (the same STIX id) with the Enterprise technique of the same name and its mitigation."""
    return [
        _object(ENTERPRISE, SANDWORM, AttackObjectType.GROUP, "G0034", "Sandworm Team", "ELECTRUM"),
        _object(ENTERPRISE, VALID_IT, AttackObjectType.TECHNIQUE, "T1078", "Valid Accounts"),
        _object(ENTERPRISE, MFA_IT, AttackObjectType.MITIGATION, "M1032", MFA),
        _link(ENTERPRISE, AttackLink.USES, SANDWORM, VALID_IT, "Sandworm Team has used stolen credentials."),
        _link(ENTERPRISE, AttackLink.MITIGATES, MFA_IT, VALID_IT),
    ]


@pytest.fixture
def attack() -> AttackRepository:
    get_mongodb()[Collection.ATTACK].delete_many({})
    store = get_attack_repository()
    store.create_indexes()
    return store


@pytest.fixture
def loaded(attack: AttackRepository) -> AttackRepository:
    attack.replace_source(ICS, ics_graph(), "v1")
    attack.replace_source(ENTERPRISE, enterprise_graph(), "v1")
    return attack


@pytest.fixture
def links() -> ControlLinkRepository:
    get_mongodb()[Collection.CONTROL_LINKS].delete_many({})
    return get_control_link_repository()


def _ids(store: AttackRepository, **where: Any) -> set[str]:
    return {doc["_id"] for doc in store.list(("_id",), **where)}


def test_replacing_a_source_stores_its_graph_stamped_with_source_and_version(attack: AttackRepository) -> None:
    assert not attack.has_data()
    assert attack.replace_source(ICS, ics_graph(), "v1") == 8
    assert attack.has_data()
    stored = attack.get(_id=attack_doc_id(ICS, SANDWORM))
    assert stored is not None
    assert (stored["source"], stored["version"], stored[SCHEMA_VERSION_FIELD]) == (ICS, "v1", 1)
    assert attack.count(source=ICS, version="v1") == 8


def test_a_new_version_drops_what_the_source_no_longer_has_and_leaves_the_other_source(
    loaded: AttackRepository,
) -> None:
    kept = [doc for doc in ics_graph() if doc.get("stix_id") != UNUSED]
    assert loaded.replace_source(ICS, kept, "v2") == 7
    assert attack_doc_id(ICS, UNUSED) not in _ids(loaded, source=ICS)
    assert loaded.count(source=ICS) == loaded.count(source=ICS, version="v2") == 7
    assert loaded.count(source=ENTERPRISE, version="v1") == 5


def test_a_replace_that_stops_half_way_keeps_the_earlier_graph_and_a_rerun_finishes_it(
    loaded: AttackRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mutation: delete the old version before writing the new one, and the source is empty at the stop."""
    monkeypatch.setattr(IntelLimits, "BATCH_SIZE", 3)
    kept = [doc for doc in ics_graph() if doc.get("stix_id") != UNUSED]

    def cut_short() -> Iterator[dict[str, Any]]:
        yield from kept[:4]
        raise ConnectionError("the worker died")

    with pytest.raises(ConnectionError):
        loaded.replace_source(ICS, cut_short(), "v2")
    assert _ids(loaded, source=ICS) == {doc["_id"] for doc in ics_graph()}  # nothing lost: old and new mixed
    assert loaded.count(source=ICS, version="v2") == 3  # the one full batch
    assert loaded.replace_source(ICS, kept, "v2") == 7
    assert _ids(loaded, source=ICS) == {doc["_id"] for doc in kept}
    assert loaded.count(source=ICS, version="v1") == 0


def test_an_empty_load_never_empties_a_source_that_had_data(loaded: AttackRepository) -> None:
    assert loaded.replace_source(ICS, [], "v2") == 0
    assert loaded.count(source=ICS, version="v1") == 8


def test_has_data_needs_a_document_of_each_source_asked_for(loaded: AttackRepository) -> None:
    assert loaded.has_data({ICS, ENTERPRISE}) and loaded.has_data({ICS})
    assert loaded.delete(source=ICS) == 8  # as before its first import
    assert loaded.has_data() and loaded.has_data({ENTERPRISE})
    assert not loaded.has_data({ICS}) and not loaded.has_data({ICS, ENTERPRISE})  # each source asked for is needed
    assert loaded.delete(source=ENTERPRISE) == 5 and not loaded.has_data()


def test_objects_are_found_by_attack_id_or_by_a_name_or_alias_key_in_one_read(loaded: AttackRepository) -> None:
    found = loaded.find_objects(["T0859", "M0932", "T9999"], ["voodoo bear"])
    assert sorted((doc["source"], doc["attack_id"]) for doc in found) == [
        (ICS, "G0034"),
        (ICS, "M0932"),
        (ICS, "T0859"),
    ]
    technique = next(doc for doc in found if doc["attack_id"] == "T0859")
    assert set(technique) == {
        "source",
        "stix_id",
        "type",
        "attack_id",
        "name",
        "aliases",
        "name_keys",
        "description",
        "url",
    }
    assert technique["type"] == AttackObjectType.TECHNIQUE and technique["stix_id"] == VALID_ICS


def test_an_object_both_sources_hold_comes_back_once_per_source_and_a_shared_name_gives_every_match(
    loaded: AttackRepository,
) -> None:
    by_id = loaded.find_objects(["G0034"], [])
    assert sorted(doc["source"] for doc in by_id) == [ENTERPRISE, ICS] and {doc["stix_id"] for doc in by_id} == {
        SANDWORM
    }
    by_name = loaded.find_objects([], ["valid accounts"])
    assert sorted(doc["attack_id"] for doc in by_name) == ["T0859", "T1078"]  # the caller sees it is not unique


def test_no_id_and_no_key_asks_the_database_nothing(loaded: AttackRepository, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AttackRepository, "collection", property(lambda self: pytest.fail("a read was made")))
    assert loaded.find_objects([], []) == []
    assert loaded.find_uses([], [VALID_ICS]) == [] and loaded.find_uses([SANDWORM], []) == []
    assert loaded.find_mitigations([]) == []


def test_relationships_are_never_returned_as_objects(loaded: AttackRepository) -> None:
    loaded.collection.update_one(
        {"_id": attack_doc_id(ICS, f"relationship--uses-{SANDWORM}-{VALID_ICS}")}, {"$set": {"attack_id": "T0859"}}
    )
    assert [doc["stix_id"] for doc in loaded.find_objects(["T0859"], [])] == [VALID_ICS]


def test_uses_are_found_for_the_named_groups_and_techniques_only(loaded: AttackRepository) -> None:
    uses = loaded.find_uses([SANDWORM], [VALID_ICS])
    assert uses == [
        {
            "source": ICS,
            "source_ref": SANDWORM,
            "target_ref": VALID_ICS,
            "description": "Sandworm Team used valid accounts in the 2015 attack.",
            "citations": [{"name": "Report", "url": "https://example.test/report"}],
        }
    ]
    both = loaded.find_uses([SANDWORM], [VALID_ICS, VALID_IT])
    assert sorted(use["target_ref"] for use in both) == sorted([VALID_ICS, VALID_IT])
    assert loaded.find_uses([SANDWORM], [MFA_ICS]) == []  # a "mitigates" link is never a use


def test_a_link_of_another_kind_or_from_a_group_not_asked_for_is_never_a_use(loaded: AttackRepository) -> None:
    """Mutation: drop the type from find_uses and "M0932 mitigates T0859" reads as a use; drop the group and
    every group's use of the technique comes back for the one asked."""
    assert loaded.find_uses([MFA_ICS], [VALID_ICS]) == []  # the stored link between these two is "mitigates"
    assert loaded.find_uses(["intrusion-set--another"], [VALID_ICS, VALID_IT]) == []  # Sandworm's uses are not its


def test_only_the_asked_groups_uses_are_read_from_the_database(
    loaded: AttackRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid Accounts is used by many groups. Mutation: drop the groups from the uses query and every group's
    use of the technique is read, then thrown away."""
    loaded.replace_source(
        ICS, [*ics_graph(), _link(ICS, AttackLink.USES, "intrusion-set--another", VALID_ICS, "Theirs.")], "v2"
    )
    read_rows, read = [], AttackRepository.list

    def counted(self: AttackRepository, *fields: Any, **where: Any) -> list[dict[str, Any]]:
        rows = read(self, *fields, **where)
        read_rows.extend(rows)
        return rows

    monkeypatch.setattr(AttackRepository, "list", counted)
    assert len(loaded.find_uses([SANDWORM], [VALID_ICS])) == 1
    assert [row["source_ref"] for row in read_rows] == [SANDWORM]


def test_a_use_recorded_on_a_groups_campaign_is_found_as_the_groups_use(loaded: AttackRepository) -> None:
    """ATT&CK ICS records "Sandworm Team used valid accounts" on its 2015 and 2016 campaigns, not on the group
    (live data, 17 Nov 2026: 35 of its 74 group and technique pairs). Mutation: read only the groups' own
    links and the first use is not found; drop the group from the attribution read and the last one is."""
    campaign, second, theirs = "campaign--ukraine-2015", "campaign--ukraine-2016", "campaign--another"
    spearphishing, other_group = "attack-pattern--spearphishing", "intrusion-set--another"
    told = "During the 2015 attack, Sandworm Team sent spearphishing attachments."
    loaded.replace_source(
        ICS,
        [
            *ics_graph(),
            _object(ICS, spearphishing, AttackObjectType.TECHNIQUE, "T0865", "Spearphishing Attachment"),
            *(_object(ICS, ref, AttackObjectType.CAMPAIGN, f"C00{n}", ref) for n, ref in enumerate((campaign, second))),
            *(_link(ICS, AttackLink.ATTRIBUTED_TO, ref, SANDWORM) for ref in (campaign, second)),
            _link(ICS, AttackLink.USES, campaign, spearphishing, told),
            _link(ICS, AttackLink.USES, second, spearphishing),  # no text: the campaign that tells it is kept
            _link(ICS, AttackLink.USES, campaign, VALID_ICS, "Told on the campaign too."),
            _link(ICS, AttackLink.ATTRIBUTED_TO, theirs, other_group),
            _link(ICS, AttackLink.USES, theirs, VALID_IT, "Another group's campaign."),
        ],
        "v2",
    )
    cited = [{"name": "Report", "url": "https://example.test/report"}]
    through = {"source": ICS, "source_ref": SANDWORM, "target_ref": spearphishing, "description": told}
    assert loaded.find_uses([SANDWORM], [spearphishing]) == [through | {"citations": cited}]
    own = loaded.find_uses([SANDWORM], [VALID_ICS])  # the group's own record stands, once
    assert [use["description"] for use in own] == ["Sandworm Team used valid accounts in the 2015 attack."]
    assert [use["source"] for use in loaded.find_uses([SANDWORM], [VALID_IT])] == [ENTERPRISE]  # never another group's


def test_of_a_groups_campaigns_using_one_technique_the_one_that_tells_how_is_kept(loaded: AttackRepository) -> None:
    """Mutation: keep the first campaign by its id alone and the use comes back with no text."""
    silent, telling, spearphishing = "campaign--a-2015", "campaign--b-2016", "attack-pattern--spearphishing"
    told = "During the 2016 attack, Sandworm Team sent spearphishing attachments."
    loaded.replace_source(
        ICS,
        [
            *ics_graph(),
            *(_link(ICS, AttackLink.ATTRIBUTED_TO, ref, SANDWORM) for ref in (silent, telling)),
            _link(ICS, AttackLink.USES, silent, spearphishing),  # no text, and first by its id
            _link(ICS, AttackLink.USES, telling, spearphishing, told),
        ],
        "v2",
    )
    assert [use["description"] for use in loaded.find_uses([SANDWORM], [spearphishing])] == [told]


def test_mitigations_come_back_for_the_techniques_asked_for_only(loaded: AttackRepository) -> None:
    """Mutation: drop the technique from find_mitigations and T1078's mitigation is read as one of T0859."""
    found = loaded.find_mitigations([VALID_ICS])
    assert [(row["technique_ref"], row["attack_id"]) for row in found] == [(VALID_ICS, "M0932")]


def test_mitigations_of_each_technique_come_in_one_read_without_the_entries_that_mitigate_nothing(
    loaded: AttackRepository,
) -> None:
    """Mutation: drop the NOT_MITIGATIONS filter and M0816 shows as a defence of T0859."""
    assert "M0816" in ControlLinks.NOT_MITIGATIONS
    found = loaded.find_mitigations([VALID_ICS, VALID_IT, "attack-pattern--unknown"])
    assert found == [
        {"source": ICS, "technique_ref": VALID_ICS, "mitigation_ref": MFA_ICS, "attack_id": "M0932", "name": MFA},
        {"source": ENTERPRISE, "technique_ref": VALID_IT, "mitigation_ref": MFA_IT, "attack_id": "M1032", "name": MFA},
    ]


def test_the_mitigations_to_link_are_the_ones_a_technique_names_once_each(loaded: AttackRepository) -> None:
    second = "attack-pattern--second"
    loaded.replace_source(
        ICS,
        [
            *ics_graph(),
            _object(ICS, second, AttackObjectType.TECHNIQUE, "T0886", "Remote Services"),
            _link(ICS, AttackLink.MITIGATES, MFA_ICS, second),
        ],
        "v2",
    )
    about = {"name": MFA, "description": f"{MFA} described."}
    assert loaded.list_mitigations() == [
        {"source": ICS, "stix_id": MFA_ICS, "attack_id": "M0932"} | about,
        {"source": ENTERPRISE, "stix_id": MFA_IT, "attack_id": "M1032"} | about,
    ]


def test_every_read_of_the_graph_is_served_by_an_index(loaded: AttackRepository) -> None:
    """Mutation: drop one index of AttackRepository and its read scans the whole collection."""
    own = {"by_attack_id", "by_name_key", "by_type_and_source_ref", "by_type_and_target_ref", "by_source_and_version"}
    assert set(loaded.collection.index_information()) == own | {"_id_"}
    reads = [
        {"record": AttackRecord.OBJECT, "$or": [{"attack_id": {"$in": ["T0859"]}}, {"name_keys": {"$in": ["x"]}}]},
        {"type": AttackLink.USES, "source_ref": {"$in": [SANDWORM]}, "target_ref": {"$in": [VALID_ICS]}},
        {"type": AttackLink.MITIGATES, "target_ref": {"$in": [VALID_ICS]}},
        {"type": AttackLink.MITIGATES},
        {"source": ICS, "version": {"$ne": "v1"}},
    ]
    for read in reads:
        plan = str(loaded.collection.find(read).explain()["queryPlanner"]["winningPlan"])
        assert "IXSCAN" in plan and "COLLSCAN" not in plan, read


def _saved(mitigation_id: str, control_ids: list[int], prepared_at: datetime, fingerprint: str = "f") -> dict[str, Any]:
    made = [
        {"control_id": control_id, "effect": ControlEffect.PREVENT, "reason": "It does this.", "rerank": 91.5}
        for control_id in control_ids
    ]
    return {
        "_id": mitigation_id,
        "name": "A mitigation",
        "fingerprint": fingerprint,
        "links": made,
        "prepared_at": prepared_at,
    }


def test_a_saved_link_is_read_back_by_mitigation_and_saving_again_replaces_it(links: ControlLinkRepository) -> None:
    links.save_link(_saved("M0932", [412, 87, 530], NOW, "first"))
    links.save_link(_saved("M0801", [], NOW))
    assert links.list_link_fingerprints() == {"M0932": "first", "M0801": "f"}
    found = links.find_links(["M0932", "M0801", "M0999"])
    assert [link["control_id"] for link in found["M0932"]] == [412, 87, 530] and found["M0801"] == []
    assert "M0999" not in found  # never prepared: the caller searches by meaning alone
    assert set(found["M0932"][0]) == {"control_id", "effect", "reason", "rerank"}
    links.save_link(_saved("M0932", [9], NOW, "second"))
    assert links.list_link_fingerprints()["M0932"] == "second"
    assert [link["control_id"] for link in links.find_links(["M0932"])["M0932"]] == [9]
    assert links.count() == 2


def test_no_mitigation_asks_the_database_nothing(links: ControlLinkRepository, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ControlLinkRepository, "collection", property(lambda self: pytest.fail("a read was made")))
    assert links.find_links([]) == {}


def test_the_summary_counts_linked_and_unlinked_mitigations_and_the_newest_preparation(
    links: ControlLinkRepository,
) -> None:
    nothing = {"mitigations": 0, "linked": 0, "without_links": 0, "prepared_at": None}
    assert links.summarise_links([]) == nothing | {"not_prepared": 0}
    assert links.summarise_links(["M0932", "M0801"]) == nothing | {"not_prepared": 2}
    links.save_link(_saved("M0932", [412, 87], NOW))
    links.save_link(_saved("M0801", [], NOW + timedelta(hours=1)))
    links.save_link(_saved("M0810", [5], NOW - timedelta(days=1)))
    summary = links.summarise_links(["M0932", "M0801", "M0810", "M0999", "M0999"])
    counted = (summary["mitigations"], summary["linked"], summary["without_links"], summary["not_prepared"])
    assert counted == (3, 2, 1, 1)  # M0999 is listed and has no record yet
    assert summary["prepared_at"].replace(tzinfo=UTC) == NOW + timedelta(hours=1)


def test_the_summary_counts_only_the_mitigations_it_is_given(links: ControlLinkRepository) -> None:
    """An unlisted mitigation's links are kept (listed again, it costs no AI call): they were counted as prepared.
    Mutation: drop the $match and the links of the two unlisted mitigations are counted."""
    for mitigation, prepared_at in (("M0932", NOW), ("M0801", NOW + timedelta(hours=1)), ("M0810", NOW)):
        links.save_link(_saved(mitigation, [5], prepared_at))
    summary = links.summarise_links(["M0932"])
    counted = (summary["mitigations"], summary["linked"], summary["without_links"], summary["not_prepared"])
    assert counted == (1, 1, 0, 0) and summary["prepared_at"].replace(tzinfo=UTC) == NOW
