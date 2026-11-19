"""The MITRE ATT&CK import also stores the STIX objects the MITRE run reads (ADR-010), in
tsg_mitre_enterprise_stix and tsg_mitre_ics_stix (the real MongoDB): revoked, deprecated and `targets` kept, an
unchanged release not written again, an empty collection refilled, and the import runs with the switch off
while the evidence index stays untouched."""

from typing import Any

import pytest

from app.core.constants import IntelKind, IntelSource
from app.crud.mitre.mitre_stix import (
    MitreStixRepository,
    get_mitre_enterprise_stix_repository,
    get_mitre_ics_stix_repository,
)
from app.domain.intel import refresh
from app.domain.intel.sources.attack import keep_scenario_stix_objects
from app.schemas.intel_records import FetchResult, IntelRecord
from tests.external_intelligence.evidence_fakes import NOW, MemoryKeeper, StubFetcher
from tests.external_intelligence.operations.refresh_fakes import ClaimFeeds, CurrentRecords, use_refresh_parts
from tests.external_intelligence.sources.test_mitre_attack_source import _bundle, _run

ENT, ICS = IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS
STIX = (
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Valid Accounts", "created": "dropped"},
    {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Old Group", "revoked": True},
    {"type": "tool", "id": "tool--1", "name": "Old Tool", "x_mitre_deprecated": True},
    {"type": "x-mitre-asset", "id": "x-mitre-asset--1", "name": "Control Server"},
    {"type": "x-mitre-data-source", "id": "x-mitre-data-source--1", "name": "not read"},
    {"type": "relationship", "id": "relationship--1", "relationship_type": "targets",
     "source_ref": "attack-pattern--1", "target_ref": "x-mitre-asset--1"},
    {"type": "relationship", "id": "relationship--2", "relationship_type": "detects",
     "source_ref": "x-mitre-data-source--1", "target_ref": "attack-pattern--1"},
    {"type": "relationship", "relationship_type": "uses"},  # no id: nothing to store it under
)  # fmt: skip


def test_the_kept_objects_are_the_runs_types_and_links_revoked_and_deprecated_included() -> None:
    kept = keep_scenario_stix_objects([*STIX, "not an object"])
    ids = [stix_object["id"] for stix_object in kept]
    assert ids == ["attack-pattern--1", "intrusion-set--1", "tool--1", "x-mitre-asset--1", "relationship--1"]
    assert "created" not in kept[0] and kept[1]["revoked"] is True and kept[2]["x_mitre_deprecated"] is True
    assert kept[4]["relationship_type"] == "targets"


def test_the_source_hands_the_kept_objects_to_the_import() -> None:
    result = _run(_bundle(extra=[dict(STIX[5])]))
    assert result is not None
    kept = {stix_object["id"] for stix_object in result.raw_stix}
    assert {"t--1", "t--2", "g--1", "c--1", "x--1", "relationship--1"} <= kept  # t--2 is deprecated


def fetched(stix: tuple[dict[str, Any], ...], version: str = "15.1") -> FetchResult:
    records = (IntelRecord(ENT, "T1078", IntelKind.TECHNIQUE, "IT", "Valid Accounts", "t", "https://x", version),)
    return FetchResult(records, (), f"{version}|etag-a", version, (), keep_scenario_stix_objects(list(stix)))


class Importer:
    """The refresh over in-memory feeds and records and the real MITRE STIX collections."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, switch_on: bool = True) -> None:
        self.feeds, self.keeper = ClaimFeeds([ENT, ICS]), MemoryKeeper()
        self.fetchers = {ENT: StubFetcher(ENT, None), ICS: StubFetcher(ICS, None)}
        parts = {"records": CurrentRecords(), "feeds": self.feeds, "keeper": self.keeper, "switch_on": switch_on}
        self.run = use_refresh_parts(monkeypatch, self.fetchers, **parts)
        stores = {ENT: get_mitre_enterprise_stix_repository(), ICS: get_mitre_ics_stix_repository()}
        monkeypatch.setattr(refresh, "_scenario_stix_repository", stores.__getitem__)

    def fetch(self, result: FetchResult | None, source: IntelSource = ENT) -> Any:
        self.fetchers[source].result = result
        return self.run.refresh_one_source(source, NOW)


@pytest.fixture
def enterprise() -> MitreStixRepository:
    store = get_mitre_enterprise_stix_repository()
    store.collection.delete_many({})
    return store


def test_an_import_stores_the_kept_objects_and_an_unchanged_release_is_not_written_again(
    monkeypatch: pytest.MonkeyPatch, enterprise: MitreStixRepository
) -> None:
    importer = Importer(monkeypatch)
    importer.fetch(fetched(STIX))
    assert enterprise.stored_versions() == ["15.1"] and enterprise.count() == 5
    assert enterprise.get(_id="relationship--1")["relationship_type"] == "targets"  # type: ignore[index]
    monkeypatch.setattr(enterprise, "replace_stix_objects", lambda *_: pytest.fail("an unchanged release written"))
    importer.fetch(fetched(STIX))  # a new ETag on the same release


def test_an_emptied_collection_is_refilled_although_the_file_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, enterprise: MitreStixRepository
) -> None:
    """Mutation: trust the checkpoint without the STIX guard and the server's 304 keeps the collection empty."""
    importer = Importer(monkeypatch)
    importer.fetch(fetched(STIX))
    importer.fetch(None)
    assert importer.fetchers[ENT].checkpoints[-1] == "15.1|etag-a"  # stored whole: the checkpoint holds
    enterprise.collection.delete_many({})
    importer.fetch(fetched(STIX))
    assert importer.fetchers[ENT].checkpoints[-1] is None  # read again, whatever the server's ETag says
    assert enterprise.count() == 5


def test_an_import_without_stix_objects_never_empties_the_collection(
    monkeypatch: pytest.MonkeyPatch, enterprise: MitreStixRepository
) -> None:
    importer = Importer(monkeypatch)
    importer.fetch(fetched(STIX))
    importer.fetch(fetched((), version="15.2"))
    assert enterprise.stored_versions() == ["15.1"] and enterprise.count() == 5


def test_the_import_runs_with_the_switch_off_and_the_evidence_index_stays_untouched(
    monkeypatch: pytest.MonkeyPatch, enterprise: MitreStixRepository
) -> None:
    importer = Importer(monkeypatch, switch_on=False)
    summary = importer.fetch(fetched(STIX))
    assert enterprise.count() == 5 and summary.failed == ()
    assert summary.index_rebuilt is False and importer.keeper.rebuilds == 0  # evidence stays gated


def test_the_evidence_index_is_rebuilt_after_an_import_while_the_switch_is_on(
    monkeypatch: pytest.MonkeyPatch, enterprise: MitreStixRepository
) -> None:
    importer = Importer(monkeypatch)
    assert importer.fetch(fetched(STIX)).index_rebuilt is True and importer.keeper.rebuilds == 1
