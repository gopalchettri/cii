"""The record store against the real MongoDB: idempotent versioned saves, retire, streams."""

from datetime import UTC, datetime

import pytest

from app.core.constants import Collection, IntelKind, IntelSource
from app.core.database import get_mongodb
from app.crud.intel import IntelRecordRepository, get_intel_record_repository
from app.schemas.intel_records import IntelRecord

NOW = datetime(2026, 10, 12, tzinfo=UTC)
SOURCE = IntelSource.ATTACK_ENTERPRISE


@pytest.fixture
def store() -> IntelRecordRepository:
    db = get_mongodb()
    db[Collection.INTEL].delete_many({})
    records = get_intel_record_repository()
    records.create_indexes()
    return records


def _record(external_id: str = "T0001", text: str = "first", source: IntelSource = SOURCE) -> IntelRecord:
    return IntelRecord(source, external_id, IntelKind.TECHNIQUE, "IT", "t", text, "https://x.test", "v1")


def _current_ids(store: IntelRecordRepository, source: IntelSource) -> set[str]:
    return {doc["external_id"] for doc in store.list(["external_id"], source=source, current=True)}


def _all_docs() -> list[dict]:
    return list(get_mongodb()[Collection.INTEL].find({}, {"_id": 0, "fetched_at": 0}))


def test_saving_an_unchanged_record_twice_stores_it_once(store: IntelRecordRepository) -> None:
    assert store.save_intel_records([_record()], NOW) == 1
    assert store.save_intel_records([_record()], NOW) == 0
    assert store.count(sources=[SOURCE], current=True) == 1


def test_changed_content_is_a_new_version_and_the_old_one_stops_being_current(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record(text="first")], NOW)
    store.save_intel_records([_record(text="second")], NOW)
    assert [doc["text"] for doc in store.stream_current_intel_records()] == ["second"]
    assert get_mongodb()[Collection.INTEL].count_documents({"external_id": "T0001"}) == 2


def test_a_version_that_comes_back_is_current_again_and_only_one_is_current(store: IntelRecordRepository) -> None:
    for text in ("first", "second", "first"):
        store.save_intel_records([_record(text=text)], NOW)
    assert [doc["text"] for doc in store.stream_current_intel_records()] == ["first"]
    assert get_mongodb()[Collection.INTEL].count_documents({"current": True}) == 1


def test_the_same_batch_saved_in_two_halves_and_again_gives_the_same_state(store: IntelRecordRepository) -> None:
    batch = [_record(f"T{n:04d}", text=f"t{n}") for n in range(30)]
    store.save_intel_records(batch, NOW)
    expected = sorted(_all_docs(), key=lambda doc: doc["external_id"])
    get_mongodb()[Collection.INTEL].delete_many({})
    store.save_intel_records(batch[:12], NOW)  # killed here
    store.save_intel_records(batch, NOW)  # the run starts over
    store.save_intel_records(batch, NOW)
    assert sorted(_all_docs(), key=lambda doc: doc["external_id"]) == expected


def test_retire_removes_only_what_a_complete_fetch_no_longer_has(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record("T0001"), _record("T0002"), _record("T0003")], NOW)
    store.save_intel_records([_record("T0009", source=IntelSource.ATTACK_ICS)], NOW)
    assert store.retire_intel_records_missing_from(SOURCE, {"T0001", "T0003"}, NOW) == 1
    assert _current_ids(store, SOURCE) == {"T0001", "T0003"}
    assert _current_ids(store, IntelSource.ATTACK_ICS) == {"T0009"}
    assert get_mongodb()[Collection.INTEL].count_documents({"external_id": "T0002"}) == 1  # history stays


def test_retire_with_an_empty_answer_retires_nothing(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record()], NOW)
    assert store.retire_intel_records_missing_from(SOURCE, set(), NOW) == 0
    assert store.count(sources=[SOURCE], current=True) == 1


def test_a_retired_record_that_returns_is_current_again(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record("T0001"), _record("T0002")], NOW)
    store.retire_intel_records_missing_from(SOURCE, {"T0001"}, NOW)
    store.save_intel_records([_record("T0002")], NOW)
    assert _current_ids(store, SOURCE) == {"T0001", "T0002"}


def test_streaming_and_counting_cover_the_asked_sources_only(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record(), _record("T1", source=IntelSource.ATTACK_ICS)], NOW)
    both = [SOURCE, IntelSource.ATTACK_ICS]
    assert store.count(sources=both, current=True) == 2 and store.count(sources=[SOURCE], current=True) == 1
    doc = next(iter(store.stream_current_intel_records()))
    assert "_id" not in doc and "current" not in doc and doc["external_id"] == "T0001"


def test_a_record_of_a_source_outside_the_registry_is_never_streamed(store: IntelRecordRepository) -> None:
    store.save_intel_records([_record(), _record("T1", source=IntelSource.ATTACK_ICS)], NOW)
    store.collection.update_one({"external_id": "T1"}, {"$set": {"source": "cisa_kev"}})
    assert [doc["external_id"] for doc in store.stream_current_intel_records()] == ["T0001"]
