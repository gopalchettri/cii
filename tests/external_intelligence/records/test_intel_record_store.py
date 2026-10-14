"""The record store against the real MongoDB: idempotent versioned saves, quarantine, retire, purge,
streams."""

from datetime import UTC, datetime

import pytest

from app.core.constants import Collection, IntelKind, IntelRejection, IntelSource
from app.core.database import get_mongodb
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord

NOW = datetime(2026, 10, 12, tzinfo=UTC)
SOURCE = IntelSource.CISA_KEV


@pytest.fixture
def store() -> IntelRecordStore:
    db = get_mongodb()
    db[Collection.INTEL].delete_many({})
    records = IntelRecordStore(db)
    records.ensure_indexes()
    return records


def _record(
    external_id: str = "CVE-2024-0001", text: str = "first", source: IntelSource = SOURCE
) -> IntelRecord:
    return IntelRecord(source, external_id, IntelKind.VULNERABILITY, "IT", "t", text, "https://x.test", "v1")


def _all_docs() -> list[dict]:
    return list(get_mongodb()[Collection.INTEL].find({}, {"_id": 0, "fetched_at": 0}))


def test_saving_an_unchanged_record_twice_stores_it_once(store: IntelRecordStore) -> None:
    assert store.save_batch([_record()], [], NOW).new_versions == 1
    again = store.save_batch([_record()], [], NOW)
    assert (again.new_versions, again.unchanged) == (0, 1)
    assert store.count_current_records([SOURCE]) == 1


def test_changed_content_is_a_new_version_and_the_old_one_stops_being_current(
    store: IntelRecordStore,
) -> None:
    store.save_batch([_record(text="first")], [], NOW)
    store.save_batch([_record(text="second")], [], NOW)
    assert [doc["text"] for doc in store.stream_current_records([SOURCE])] == ["second"]
    assert get_mongodb()[Collection.INTEL].count_documents({"external_id": "CVE-2024-0001"}) == 2


def test_a_version_that_comes_back_is_current_again_and_only_one_is_current(store: IntelRecordStore) -> None:
    for text in ("first", "second", "first"):
        store.save_batch([_record(text=text)], [], NOW)
    assert [doc["text"] for doc in store.stream_current_records([SOURCE])] == ["first"]
    assert get_mongodb()[Collection.INTEL].count_documents({"current": True}) == 1


def test_a_rejected_record_is_kept_once_with_its_reason_and_never_current(store: IntelRecordStore) -> None:
    bad = RejectedRecord(SOURCE, "CVE-bad", IntelRejection.UNSAFE_TEXT, "hash1")
    assert store.save_batch([], [bad], NOW).quarantined == 1
    assert store.save_batch([], [bad], NOW).quarantined == 0  # already stored: not new
    assert get_mongodb()[Collection.INTEL].count_documents({"external_id": "CVE-bad"}) == 1
    assert store.count_current_records([SOURCE]) == 0 and list(store.stream_current_records([SOURCE])) == []


def test_the_same_batch_saved_in_two_halves_and_again_gives_the_same_state(store: IntelRecordStore) -> None:
    batch = [_record(f"CVE-2024-{n:04d}", text=f"t{n}") for n in range(30)]
    store.save_batch(batch, [], NOW)
    expected = sorted(_all_docs(), key=lambda doc: doc["external_id"])
    get_mongodb()[Collection.INTEL].delete_many({})
    store.save_batch(batch[:12], [], NOW)  # killed here
    store.save_batch(batch, [], NOW)  # the run starts over
    store.save_batch(batch, [], NOW)
    assert sorted(_all_docs(), key=lambda doc: doc["external_id"]) == expected


def test_retire_removes_only_what_a_complete_fetch_no_longer_has(store: IntelRecordStore) -> None:
    store.save_batch([_record("CVE-2024-0001"), _record("CVE-2024-0002"), _record("CVE-2024-0003")], [], NOW)
    store.save_batch([_record("CVE-2024-0009", source=IntelSource.FIRST_EPSS)], [], NOW)
    assert store.retire_records_missing_from(SOURCE, {"CVE-2024-0001", "CVE-2024-0003"}, NOW) == 1
    assert store.list_current_external_ids(SOURCE) == {"CVE-2024-0001", "CVE-2024-0003"}
    assert store.list_current_external_ids(IntelSource.FIRST_EPSS) == {"CVE-2024-0009"}
    assert (
        get_mongodb()[Collection.INTEL].count_documents({"external_id": "CVE-2024-0002"}) == 1
    )  # history stays


def test_retire_with_an_empty_answer_retires_nothing(store: IntelRecordStore) -> None:
    store.save_batch([_record()], [], NOW)
    assert store.retire_records_missing_from(SOURCE, set(), NOW) == 0
    assert store.count_current_records([SOURCE]) == 1


def test_a_retired_record_that_returns_is_current_again(store: IntelRecordStore) -> None:
    store.save_batch([_record("CVE-2024-0001"), _record("CVE-2024-0002")], [], NOW)
    store.retire_records_missing_from(SOURCE, {"CVE-2024-0001"}, NOW)
    store.save_batch([_record("CVE-2024-0002")], [], NOW)
    assert store.list_current_external_ids(SOURCE) == {"CVE-2024-0001", "CVE-2024-0002"}


def test_streaming_and_counting_cover_the_asked_sources_only(store: IntelRecordStore) -> None:
    store.save_batch([_record(), _record("T1", source=IntelSource.ATTACK_ENTERPRISE)], [], NOW)
    both = [SOURCE, IntelSource.ATTACK_ENTERPRISE]
    assert store.count_current_records(both) == 2 and store.count_current_records([SOURCE]) == 1
    doc = next(iter(store.stream_current_records([SOURCE])))
    assert "_id" not in doc and "current" not in doc and doc["external_id"] == "CVE-2024-0001"


def test_purging_a_source_deletes_all_its_versions_and_rejections_and_nothing_else(
    store: IntelRecordStore,
) -> None:
    store.save_batch([_record(text="a")], [RejectedRecord(SOURCE, "x", IntelRejection.NO_NAME, "h")], NOW)
    store.save_batch([_record(text="b")], [], NOW)
    store.save_batch([_record("T1", source=IntelSource.ATTACK_ENTERPRISE)], [], NOW)
    assert store.purge_source(SOURCE) == 3
    assert [doc["source"] for doc in _all_docs()] == [IntelSource.ATTACK_ENTERPRISE]
