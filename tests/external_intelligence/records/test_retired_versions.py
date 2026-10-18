"""Old versions of a record are stamped when they stop being current and a TTL index deletes them, so a score
that changes every day cannot grow the collection for ever."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.constants import Collection, IntelKind, IntelOperationsLimits, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.repository import (
    IntelRecordRepository,
    intel_records,
)
from app.models.external_intelligence.intel_record import IntelRecord

DAY1 = datetime(2026, 10, 1, tzinfo=UTC)
DAY2 = DAY1 + timedelta(days=1)
SOURCE = IntelSource.FIRST_EPSS
SECONDS = IntelOperationsLimits.RETIRED_VERSION_DAYS * 86_400


@pytest.fixture
def store() -> IntelRecordRepository:
    db = get_mongodb()
    db[Collection.INTEL].delete_many({})
    records = intel_records
    records.create_indexes()
    return records


def _record(text: str, external_id: str = "CVE-1") -> IntelRecord:
    return IntelRecord(SOURCE, external_id, IntelKind.EXPLOIT_SCORE, "IT", "t", text, "https://x", "v")


def _docs() -> dict[str, dict]:
    return {doc["text"]: doc for doc in get_mongodb()[Collection.INTEL].find({})}


def test_a_superseded_version_is_stamped_and_the_current_one_is_not(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record("0.1")], [], DAY1)
    store.save_intel_records([_record("0.2")], [], DAY2)
    docs = _docs()
    assert docs["0.1"]["current"] is False and docs["0.1"]["retired_at"] == DAY2
    assert docs["0.2"]["current"] is True and "retired_at" not in docs["0.2"]


def test_a_retired_record_is_stamped_and_a_version_that_returns_loses_the_stamp(
    store: IntelRecordRepository,
) -> None:
    store.save_intel_records([_record("a"), _record("b", "CVE-2")], [], DAY1)
    assert store.retire_intel_records_missing_from(SOURCE, {"CVE-1"}, DAY2) == 1
    assert _docs()["b"]["retired_at"] == DAY2 and "retired_at" not in _docs()["a"]
    store.save_intel_records([_record("b", "CVE-2")], [], DAY2)
    assert "retired_at" not in _docs()["b"] and _docs()["b"]["current"] is True


def test_the_stamp_has_a_ttl_index_of_the_retention(store: IntelRecordRepository) -> None:
    index = get_mongodb()[Collection.INTEL].index_information()["retired_at_1"]
    assert index["expireAfterSeconds"] == SECONDS == 90 * 86_400


def test_a_changed_retention_updates_the_index_instead_of_failing_start_up(
    store: IntelRecordRepository,
) -> None:
    collection = get_mongodb()[Collection.INTEL]
    collection.database.command(
        "collMod", collection.name, index={"keyPattern": {"retired_at": 1}, "expireAfterSeconds": 5}
    )
    assert collection.index_information()["retired_at_1"]["expireAfterSeconds"] == 5
    store.create_indexes()  # a different retention than the stored one must not raise
    assert collection.index_information()["retired_at_1"]["expireAfterSeconds"] == SECONDS
