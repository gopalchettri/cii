"""tsg_mitre_*_stix against the real MongoDB: an import replaces a domain's objects whole, never emptied by an
empty or a half-finished import (ADR-010)."""

import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from app.core.constants import IntelLimits
from app.core.database import get_mongodb
from app.crud.mitre import mitre_stix
from app.crud.mitre.mitre_stix import MitreStixRepository

BATCH = IntelLimits.BATCH_SIZE


@pytest.fixture
def stix() -> Iterator[MitreStixRepository]:
    name = f"test_mitre_stix_{uuid.uuid4().hex}"  # its own collection: parallel tests never share it
    store = MitreStixRepository(name)
    store.create_indexes()
    yield store
    get_mongodb().drop_collection(name)


def test_an_import_replaces_the_objects_whole_and_an_empty_one_keeps_them(stix: MitreStixRepository) -> None:
    assert stix.stored_versions() == [] and stix.get(("_id",)) is None
    first = [
        {"id": "intrusion-set--a", "type": "intrusion-set", "name": "A", "revoked": True},
        {"id": "attack-pattern--b", "type": "attack-pattern", "name": "B"},
    ]
    assert stix.replace_stix_objects(first, "v1") == 2
    assert stix.stored_versions() == ["v1"]
    assert stix.replace_stix_objects([first[1]], "v2") == 1
    assert stix.stored_versions() == ["v2"]
    assert stix.list_stix_objects() == [{"id": "attack-pattern--b", "type": "attack-pattern", "name": "B"}]
    assert stix.replace_stix_objects([], "v3") == 0  # nothing imported: the stored objects stay
    assert stix.stored_versions() == ["v2"]


def test_an_import_stopped_half_way_never_looks_complete(
    stix: MitreStixRepository, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Batch 2 fails: the stored version keeps the writing mark, so the import's checkpoint guard (stored
    versions == [the release]) does not trust it and the next import rewrites the collection."""
    calls = {"count": 0}
    real_bulk_write = mitre_stix.bulk_write

    def fail_on_second_batch(*args: Any, **kwargs: Any) -> Any:
        calls["count"] += 1
        if calls["count"] == 2:
            raise ConnectionError("worker killed")
        return real_bulk_write(*args, **kwargs)

    monkeypatch.setattr(mitre_stix, "bulk_write", fail_on_second_batch)
    objects = [{"id": f"attack-pattern--{number}", "type": "attack-pattern"} for number in range(BATCH + 1)]
    with pytest.raises(ConnectionError):
        stix.replace_stix_objects(objects, "v1")
    assert stix.stored_versions() == ["v1|writing"]
    monkeypatch.setattr(mitre_stix, "bulk_write", real_bulk_write)
    assert stix.replace_stix_objects(objects, "v1") == BATCH + 1
    assert stix.stored_versions() == ["v1"] and stix.count(version="v1") == BATCH + 1
