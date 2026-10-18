"""MongoRepository on a scratch collection of the test database: each base read and write, a named
condition, only_if, a duplicate key, update many, update_and_get in sort order and the bulk helper."""

from collections.abc import Iterator

import pytest
from pymongo import InsertOne
from pymongo.errors import OperationFailure, WriteError

from app.core.constants import Collection
from app.core.database import get_mongodb
from app.core.exceptions import DuplicateRecord
from app.data_access.base import MongoRepository, schema_version_of

SCRATCH = "tsg_test_base_repository"


@pytest.fixture
def records() -> Iterator[MongoRepository]:
    """A repository with one unique index, an expiry, a fixed and a value-taking condition, a field list."""
    get_mongodb().drop_collection(SCRATCH)
    repository = MongoRepository(
        SCRATCH,
        indexes=[{"keys": "title", "name": "one_title", "unique": True}],
        ttl=[("expires_at", lambda: 3600)],
        conditions={
            "open": {"status": {"$ne": "done"}},
            "scores_at_least": lambda score: {"score": {"$gte": score}},
        },
        field_lists={"summary": ["title", "score"]},
    )
    repository.create_indexes()
    yield repository
    get_mongodb().drop_collection(SCRATCH)


def _add(records: MongoRepository, number: int, status: str = "new") -> None:
    records.create({"_id": f"r{number}", "title": f"title {number}", "score": number, "status": status})


def test_create_indexes_makes_the_unique_index_and_the_expiry(records: MongoRepository) -> None:
    indexes = {index["name"]: index for index in records.collection.list_indexes()}
    assert indexes["one_title"]["unique"] is True
    assert indexes["expires_at_1"]["expireAfterSeconds"] == 3600
    records.create_indexes()  # idempotent at every start-up


def test_create_returns_the_id_and_a_duplicate_names_its_index(records: MongoRepository) -> None:
    assert records.create({"_id": "r1", "title": "first"}) == "r1"
    with pytest.raises(DuplicateRecord) as refused:
        records.create({"_id": "r2", "title": "first"})
    assert refused.value.index_name == "one_title"
    with pytest.raises(DuplicateRecord) as same_id:
        records.create({"_id": "r1", "title": "other"})
    assert same_id.value.index_name == "_id_"


def test_save_inserts_replaces_and_honours_only_if(records: MongoRepository) -> None:
    assert records.save({"_id": "r1", "title": "first", "status": "new"}) is True
    assert (
        records.save({"_id": "r1", "title": "first again", "status": "done"}, only_if={"open": True}) is True
    )
    assert records.get(_id="r1")["title"] == "first again"
    assert records.save({"_id": "r1", "title": "late", "status": "new"}, only_if={"open": True}) is False
    assert records.get(_id="r1")["title"] == "first again"  # a done record is never replaced
    with pytest.raises(DuplicateRecord) as refused:
        records.save({"_id": "r2", "title": "first again"})
    assert refused.value.index_name == "one_title"


def test_get_reads_a_field_list_or_named_fields(records: MongoRepository) -> None:
    _add(records, 1)
    assert records.get("summary", _id="r1") == {"_id": "r1", "title": "title 1", "score": 1}
    assert records.get(["status"], _id="r1") == {"_id": "r1", "status": "new"}
    assert records.get(_id="missing") is None


def test_list_sorts_skips_and_limits(records: MongoRepository) -> None:
    for number in range(1, 5):
        _add(records, number)
    assert [found["_id"] for found in records.list(sort="-score")] == ["r4", "r3", "r2", "r1"]
    assert [found["_id"] for found in records.list(sort=["score"], skip=1, limit=2)] == ["r2", "r3"]
    assert [found["_id"] for found in records.list(sort="score", scores_at_least=3)] == ["r3", "r4"]


def test_count_with_a_named_condition(records: MongoRepository) -> None:
    _add(records, 1)
    _add(records, 2, status="done")
    _add(records, 3)
    assert records.count() == 3
    assert records.count(open=True) == 2
    assert records.count(open=True, scores_at_least=2) == 1
    with pytest.raises(ValueError):
        records.count(open=False)  # a fixed condition is never dropped silently


def test_a_named_condition_and_a_field_on_the_same_name_both_hold(records: MongoRepository) -> None:
    _add(records, 1, status="done")
    _add(records, 2)
    assert records.count(status="done", open=True) == 0
    assert records.filter({"status": "new", "open": True}) == {
        "status": "new",
        "$and": [{"status": {"$ne": "done"}}],
    }


def test_update_sets_fields_honours_only_if_and_many(records: MongoRepository) -> None:
    for number in range(1, 4):
        _add(records, number)
    assert records.update({"status": "done"}, only_if={"open": True}, _id="r1") == 1
    assert records.update({"status": "late"}, only_if={"open": True}, _id="r1") == 0
    assert records.get(_id="r1")["status"] == "done"
    assert records.update({"flag": True}, many=True, open=True) == 2
    assert records.count(flag=True) == 2
    assert records.update({"$inc": {"score": 10}}, _id="r2") == 1
    assert records.get(_id="r2")["score"] == 12
    with pytest.raises(ValueError):
        records.update({"status": "gone"})  # no condition: never the whole collection


def test_update_and_get_takes_the_first_in_sort_order(records: MongoRepository) -> None:
    for number in range(1, 4):
        _add(records, number)
    claimed = records.update_and_get({"status": "claimed"}, sort="-score", fields="summary", open=True)
    assert claimed == {"_id": "r3", "title": "title 3", "score": 3}
    assert records.get(_id="r3")["status"] == "claimed"
    assert records.update_and_get({"status": "x"}, _id="missing") is None


def test_delete_returns_how_many_went(records: MongoRepository) -> None:
    _add(records, 1)
    _add(records, 2, status="done")
    assert records.delete(open=True) == 1
    assert records.count() == 1
    with pytest.raises(ValueError):
        records.delete()


def test_bulk_write_skips_duplicates_and_keeps_order(records: MongoRepository) -> None:
    _add(records, 1)
    unordered = [InsertOne({"_id": "r2", "title": "a"}), InsertOne({"_id": "r1"}), InsertOne({"_id": "r3"})]
    assert records.bulk_write_skipping_duplicates(unordered, ordered=False)["nInserted"] == 2
    ordered = [InsertOne({"_id": "r4", "title": "b"}), InsertOne({"_id": "r1"}), InsertOne({"_id": "r5"})]
    assert records.bulk_write_skipping_duplicates(ordered)["nInserted"] == 1  # an ordered write stops there
    assert records.count(_id="r5") == 0
    assert records.bulk_write_skipping_duplicates([]) == {}


def test_a_collection_may_be_passed_instead_of_a_name(records: MongoRepository) -> None:
    _add(records, 1)
    assert MongoRepository(get_mongodb()[SCRATCH]).count(_id="r1") == 1


def test_create_and_save_stamp_the_schema_version_and_a_record_without_one_reads_as_1(
    records: MongoRepository,
) -> None:
    records.create({"_id": "r1", "title": "first"})
    assert records.get(_id="r1")["schema_version"] == 1
    MongoRepository(records.collection, schema_version=2).save({"_id": "r1", "title": "again"})
    assert schema_version_of(records.get(_id="r1")) == 2
    assert "schema_version" not in records.get({"title": 0}, _id="r1")  # an exclusion shows what it did
    records.collection.insert_one({"_id": "old", "title": "stored before versions"})
    assert schema_version_of(records.get(_id="old")) == 1


def test_the_validator_refuses_a_record_missing_a_required_field() -> None:
    name = f"{SCRATCH}_validated"
    get_mongodb().drop_collection(name)
    validated = MongoRepository(get_mongodb()[name], required=("_id", "title"))
    try:
        validated.create_indexes()  # a new collection: created with the validator
        validated.create_indexes()  # an existing one: collMod, idempotent
        assert validated.create({"_id": "ok", "title": "t"}) == "ok"
        with pytest.raises(WriteError):
            validated.create({"_id": "no-title"})
    finally:
        get_mongodb().drop_collection(name)


def test_the_start_up_validators_are_on_the_scenario_collections() -> None:
    for collection, field in ((Collection.SESSIONS, "entity_id"), (Collection.SCENARIOS, "session_id")):
        options = get_mongodb()[collection].options()
        assert field in options["validator"]["$jsonSchema"]["required"], collection
        assert (options["validationLevel"], options["validationAction"]) == ("moderate", "error")


class _OldServer:
    """A collection on a server that refuses collMod."""

    name = "old"

    def __init__(self) -> None:
        self.database = self

    def list_collection_names(self, **_: object) -> list[str]:
        return [self.name]

    def command(self, *_: object, **__: object) -> None:
        raise OperationFailure("no such command: collMod")


def test_a_server_refusing_the_validator_never_stops_start_up() -> None:
    MongoRepository(_OldServer(), required=("_id",)).create_indexes()  # type: ignore[arg-type]
