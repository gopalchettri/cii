"""The import stores the ATT&CK graph in tsg_attack (the real MongoDB) after the technique records, inside the
same claim: a changed graph replaces the old one whole and says so, and an unchanged one writes nothing."""

from collections.abc import Iterable
from typing import Any

import pytest

from app.core.constants import (
    AttackLink,
    AttackObjectType,
    AttackRecord,
    Collection,
    IntelKind,
    IntelMessage,
    IntelSource,
)
from app.core.database import get_mongodb
from app.crud.attack import AttackRepository, attack_doc_id, get_attack_repository
from app.domain.intel.index import EvidenceIndexRefused
from app.schemas.intel_records import FetchResult, IntelRecord, RefreshResult
from tests.external_intelligence.evidence_fakes import NOW, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords, use_refresh_parts

ENT, ICS = IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS
GROUP, TECH, MFA = "intrusion-set--1", "attack-pattern--1", "course-of-action--1"


def _object(source: IntelSource, stix_id: str, kind: str, attack_id: str, name: str) -> dict[str, Any]:
    return {
        "_id": attack_doc_id(source, stix_id),
        "record": AttackRecord.OBJECT,
        "stix_id": stix_id,
        "type": kind,
        "attack_id": attack_id,
        "name": name,
        "name_keys": [name.casefold()],
        "aliases": [],
        "description": f"{name} described.",
        "url": f"https://attack.mitre.org/{attack_id}",
    }


def _link(source: IntelSource, rel_id: str, kind: str, source_ref: str, target_ref: str) -> dict[str, Any]:
    return {
        "_id": attack_doc_id(source, rel_id),
        "record": AttackRecord.RELATIONSHIP,
        "type": kind,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "description": "It did.",
        "citations": [],
    }


def graph_of(source: IntelSource = ENT, group: str = "Sandworm Team") -> tuple[dict[str, Any], ...]:
    """A group that uses a technique a mitigation reduces: five documents."""
    return (
        _object(source, GROUP, AttackObjectType.GROUP, "G0034", group),
        _object(source, TECH, AttackObjectType.TECHNIQUE, "T1078", "Valid Accounts"),
        _object(source, MFA, AttackObjectType.MITIGATION, "M1032", "Multi-factor Authentication"),
        _link(source, "relationship--uses", AttackLink.USES, GROUP, TECH),
        _link(source, "relationship--mitigates", AttackLink.MITIGATES, MFA, TECH),
    )


def fetched(graph: Iterable[dict[str, Any]], checkpoint: str = "15.1|a", source: IntelSource = ENT) -> FetchResult:
    records = (IntelRecord(source, "T1078", IntelKind.TECHNIQUE, "IT", "Valid Accounts", "t", "https://x", "15.1"),)
    return FetchResult(records, (), checkpoint, "15.1", tuple(graph))


@pytest.fixture
def attack() -> AttackRepository:
    get_mongodb()[Collection.ATTACK].delete_many({})
    store = get_attack_repository()
    store.create_indexes()
    return store


class Importer:
    """The refresh over in-memory feeds and records and the real tsg_attack; `fetch` imports one result."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, attack: AttackRepository, keeper: MemoryKeeper | None = None):
        self.feeds, self.records = ClaimFeeds([ENT, ICS]), CurrentRecords()
        self.fetchers = {ENT: StubFetcher(ENT, None), ICS: StubFetcher(ICS, None)}
        parts = {"records": self.records, "feeds": self.feeds, "keeper": keeper or MemoryKeeper(), "attack": attack}
        self.run = use_refresh_parts(monkeypatch, self.fetchers, **parts)

    def fetch(self, result: FetchResult | None, source: IntelSource = ENT) -> Any:
        self.fetchers[source].result = result
        return self.run.refresh_one_source(source, NOW)


@pytest.fixture
def importer(monkeypatch: pytest.MonkeyPatch, attack: AttackRepository) -> Importer:
    return Importer(monkeypatch, attack)


def _ids(attack: AttackRepository, source: IntelSource = ENT) -> set[str]:
    return {doc["_id"] for doc in attack.list(("_id",), source=source)}


def test_a_first_import_stores_the_graph_after_the_records_and_says_it_changed(
    importer: Importer, attack: AttackRepository
) -> None:
    order: list[str] = []
    importer.records.after_retire = lambda: order.append(f"records stored, graph documents={attack.count()}")
    summary = importer.fetch(fetched(graph_of()))
    assert order == ["records stored, graph documents=0"]  # the technique records first
    assert summary.graph_changed is True and summary.sources[0].graph_changed is True
    assert summary.sources[0].result == RefreshResult.REFRESHED
    assert _ids(attack) == {doc["_id"] for doc in graph_of()}
    stored = attack.get(_id=attack_doc_id(ENT, GROUP))
    assert stored is not None and stored["source"] == ENT and stored["version"].startswith("15.1|")
    assert attack.find_uses([GROUP], [TECH])[0]["description"] == "It did."  # in the shape the reads expect


def test_the_same_graph_fetched_again_writes_nothing_and_says_unchanged(
    importer: Importer, attack: AttackRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new ETag on the same content: the file is read again, the graph is the one stored.
    Mutation: drop the comparison in _store_graph and every import queues the control linking again."""
    importer.fetch(fetched(graph_of()))
    monkeypatch.setattr(attack, "replace_source", lambda *_: pytest.fail("an unchanged graph was written again"))
    again = importer.fetch(fetched(graph_of(), checkpoint="15.1|b"))
    assert again.sources[0].result == RefreshResult.REFRESHED and again.sources[0].graph_changed is False
    assert again.graph_changed is False


def test_a_changed_graph_replaces_the_old_one_and_leaves_no_document_of_the_old_version(
    importer: Importer, attack: AttackRepository
) -> None:
    importer.fetch(fetched(graph_of()))
    old_version = attack.get(("version",), source=ENT)["version"]  # type: ignore[index]
    renamed = [doc for doc in graph_of(group="Sandworm") if doc["_id"] != attack_doc_id(ENT, MFA)]  # 1 changed, 1 gone
    summary = importer.fetch(fetched(renamed, checkpoint="15.2|a"))
    assert summary.graph_changed is True
    assert attack.count(source=ENT, version=old_version) == 0 and attack.count(source=ENT) == 4
    assert attack_doc_id(ENT, MFA) not in _ids(attack)
    assert attack.find_objects(["G0034"], [])[0]["name"] == "Sandworm"


@pytest.mark.parametrize(("lost", "kept", "current"), [(AttackRecord.RELATIONSHIP, 0, 2), (AttackRecord.OBJECT, 1, 3)])
def test_a_fetch_that_lost_most_of_its_links_or_its_objects_fails_and_keeps_the_stored_graph(
    importer: Importer, attack: AttackRepository, lost: AttackRecord, kept: int, current: int
) -> None:
    """Only the technique records had a cut-short rule: a file with every technique but without its links, or
    without its groups, replaced the stored graph, and each scenario lost its group, its uses or its
    mitigations. Mutation: drop the rule and both replace the graph; count the objects only and the lost links do."""
    importer.fetch(fetched(graph_of()))
    stored = attack.list(sort="_id", source=ENT)
    technique = attack_doc_id(ENT, TECH)  # the technique is still there: the records' own rule passes
    cut = [doc for doc in graph_of() if doc["record"] != lost or doc["_id"] == technique]
    summary = importer.fetch(fetched(cut, checkpoint="15.2|a"))
    outcome = summary.sources[0]
    assert outcome.result == RefreshResult.FAILED and summary.graph_changed is False
    assert outcome.error == IntelMessage.CUT_SHORT.format(source=ENT, kept=kept, current=current)
    assert attack.list(sort="_id", source=ENT) == stored  # the stored graph as it was
    assert len(importer.records.saved) == 1 and importer.feeds.health[ENT].checkpoint == "15.1|a"  # nothing written


def test_a_stored_graph_that_lost_a_document_is_written_again_by_the_same_import(
    importer: Importer, attack: AttackRepository
) -> None:
    """An earlier write that stopped half way, or a document removed by hand: the same content is not "stored".
    Mutation: compare the version alone and the missing document never comes back."""
    importer.fetch(fetched(graph_of()))
    get_mongodb()[Collection.ATTACK].delete_one({"_id": attack_doc_id(ENT, MFA)})
    assert importer.fetch(fetched(graph_of(), checkpoint="15.1|b")).graph_changed is True
    assert _ids(attack) == {doc["_id"] for doc in graph_of()}


def test_a_stored_graph_with_a_document_left_from_an_older_version_is_written_again(
    importer: Importer, attack: AttackRepository
) -> None:
    """A replace that wrote every new document and stopped before it deleted the old version.
    Mutation: count only the documents of this version and the stale one is read as ATT&CK's for good."""
    importer.fetch(fetched(graph_of()))
    stale = _object(ENT, "intrusion-set--retired", AttackObjectType.GROUP, "G0001", "Retired Group")
    get_mongodb()[Collection.ATTACK].insert_one(stale | {"source": ENT, "version": "15.0|older"})
    assert importer.fetch(fetched(graph_of(), checkpoint="15.1|b")).graph_changed is True
    assert _ids(attack) == {doc["_id"] for doc in graph_of()}


def test_a_graph_replaced_while_the_file_is_unchanged_is_read_again_by_the_next_import(
    importer: Importer, attack: AttackRepository
) -> None:
    """A stored graph that is not its release's (2026-11-17: a probe's test graph in the live database) while
    MITRE's file is unchanged: the file is downloaded whole again, never answered "unchanged" for good.
    Mutation: trust the checkpoint alone and the wrong graph stays until MITRE publishes a new file."""
    importer.fetch(fetched(graph_of()))
    get_mongodb()[Collection.ATTACK].delete_many({})
    attack.replace_source(ENT, graph_of(group="Probe Group"), "v1")
    importer.fetch(fetched(graph_of()))
    assert importer.fetchers[ENT].checkpoints == [None, None]  # read again, whatever the server's ETag says
    assert attack.find_objects(["G0034"], [])[0]["name"] == "Sandworm Team"
    importer.fetch(None)
    assert importer.fetchers[ENT].checkpoints[-1] == "15.1|a"  # its release's graph stored: the checkpoint holds


def test_a_file_that_did_not_change_and_an_import_without_a_graph_change_nothing(
    importer: Importer, attack: AttackRepository
) -> None:
    importer.fetch(fetched(graph_of()))
    unchanged = importer.fetch(None)
    assert unchanged.sources[0].result == RefreshResult.UNCHANGED and unchanged.graph_changed is False
    without_graph = importer.fetch(fetched((), checkpoint="15.1|c"))  # never empties a source that had a graph
    assert without_graph.graph_changed is False and attack.count(source=ENT) == 5


def test_the_summary_says_changed_when_any_source_changed_and_each_source_keeps_its_own_graph(
    importer: Importer, attack: AttackRepository
) -> None:
    importer.fetch(fetched(graph_of()))
    importer.fetchers[ENT].result = fetched(graph_of(), checkpoint="15.1|b")  # Enterprise: the same graph
    importer.fetchers[ICS].result = fetched(graph_of(ICS), source=ICS)  # ICS: its first
    summary = importer.run.refresh_all_sources(NOW)
    assert [(item.source, item.graph_changed) for item in summary.sources] == [(ENT, False), (ICS, True)]
    assert summary.graph_changed is True
    assert attack.count(source=ENT) == attack.count(source=ICS) == 5  # the same STIX ids, once per source


@pytest.mark.parametrize("failure", [True, EvidenceIndexRefused("nothing to index")])
def test_a_failed_index_rebuild_still_says_the_graph_changed(
    failure: bool | Exception, monkeypatch: pytest.MonkeyPatch, attack: AttackRepository
) -> None:
    """The control links are due whatever became of the evidence index."""
    summary = Importer(monkeypatch, attack, MemoryKeeper(fail=failure)).fetch(fetched(graph_of()))
    assert summary.index_rebuilt is False and summary.graph_changed is True


def test_the_claim_is_renewed_before_the_graph_is_written_and_a_lost_claim_writes_none(
    importer: Importer, attack: AttackRepository
) -> None:
    importer.fetch(fetched(graph_of()))
    assert importer.feeds.renewals == 3  # before the one batch, before the retirement, before the graph
    importer.records.after_retire = lambda: importer.feeds.claimed.update({ENT: "the-new-owner"})
    summary = importer.fetch(fetched(graph_of(group="Sandworm"), checkpoint="15.2|a"))
    assert summary.sources[0].result == RefreshResult.CLAIM_LOST and summary.graph_changed is False
    assert attack.find_objects(["G0034"], [])[0]["name"] == "Sandworm Team"  # the new owner writes its own
