"""MongoRepository on a scratch collection of the test database: each base read and write, a named
condition, only_if, a duplicate key, update many, update_and_get in sort order, the bulk helper and the
validator at start-up (a fake server for a refused or unreadable rule)."""

from collections.abc import Iterator

import pytest
from pymongo import InsertOne
from pymongo.errors import OperationFailure, WriteError
from structlog.testing import capture_logs

from app.core.constants import Collection, LogEvent
from app.core.database import get_mongodb
from app.core.exceptions import DuplicateRecord
from app.data_access.base import SCHEMA_VERSION_FIELD, MongoRepository

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
    assert records.get(_id="r1").get(SCHEMA_VERSION_FIELD, 1) == 2
    assert "schema_version" not in records.get({"title": 0}, _id="r1")  # an exclusion shows what it did
    records.collection.insert_one({"_id": "old", "title": "stored before versions"})
    assert records.get(_id="old").get(SCHEMA_VERSION_FIELD, 1) == 1


def test_the_validator_refuses_a_record_missing_a_required_field() -> None:
    name = f"{SCRATCH}_validated"
    get_mongodb().drop_collection(name)
    validated = MongoRepository(get_mongodb()[name], required=("_id", "title"))
    try:
        validated.create_indexes()  # a new collection: created with the validator
        validated.create_indexes()  # an existing one with the same rule: left alone
        assert validated.create({"_id": "ok", "title": "t"}) == "ok"
        with pytest.raises(WriteError):
            validated.create({"_id": "no-title"})
        MongoRepository(get_mongodb()[name], required=("_id",)).create_indexes()  # a field dropped: collMod
        assert validated.create({"_id": "no-title"}) == "no-title"
    finally:
        get_mongodb().drop_collection(name)


def test_the_start_up_validators_are_on_the_scenario_collections() -> None:
    for collection, field in ((Collection.SESSIONS, "entity_id"), (Collection.SCENARIOS, "session_id")):
        options = get_mongodb()[collection].options()
        assert field in options["validator"]["$jsonSchema"]["required"], collection
        assert (options["validationLevel"], options["validationAction"]) == ("moderate", "error")


MAPPING_FIELDS = ("_id", "tenant_id", "entity_id", "status", "job")


class _RefusingServer:
    """A collection (its own database) with a stored validator, on a server that refuses collMod."""

    name = "tsg_service_mappings"

    def __init__(self, stored_required: tuple[str, ...] = (), *, unreadable: bool = False) -> None:
        self.database, self.unreadable, self.commands = self, unreadable, []
        self.options = _stored_rule(stored_required) if stored_required else {}

    def list_collections(self, **_: object) -> list[dict]:
        if self.unreadable:
            raise OperationFailure("not authorized on cii_uat to execute command { listCollections: 1 }")
        return [{"name": self.name, "options": self.options}]

    def command(self, *args: object, **__: object) -> None:
        self.commands.append(args)
        raise OperationFailure("not authorized on cii_uat to execute command { collMod }", code=13)


def _stored_rule(required: tuple[str, ...]) -> dict:
    """A collection's options as MongoDB stores them for a validator requiring `required`."""
    schema = {"bsonType": "object", "required": list(required)}
    return {"validator": {"$jsonSchema": schema}, "validationLevel": "moderate", "validationAction": "error"}


def _start_up(server: _RefusingServer, required: tuple[str, ...] = MAPPING_FIELDS) -> list[dict]:
    """The log lines of create_indexes on `server` (it never raises)."""
    with capture_logs() as logs:
        MongoRepository(server, required=required).create_indexes()  # type: ignore[arg-type]
    return logs


def test_a_server_refusing_the_validator_never_stops_start_up() -> None:
    logs = _start_up(_RefusingServer(), required=("_id",))
    assert [(line["event"], line["log_level"]) for line in logs] == [
        (LogEvent.MONGODB_VALIDATOR_NOT_APPLIED, "warning")
    ]


def test_a_refused_validator_still_requiring_a_dropped_field_is_an_error_naming_the_fix() -> None:
    """UAT, 2026-10-29: the 20 Oct rule still required `generation` and collMod was refused, so every
    service-mapper insert failed (500) behind a start-up warning."""
    server = _RefusingServer((*MAPPING_FIELDS[:4], "generation", "job"))
    logs = _start_up(server)
    assert len(server.commands) == 1
    assert [(line["event"], line["log_level"]) for line in logs] == [
        (LogEvent.MONGODB_VALIDATOR_STALE, "error")
    ]
    assert logs[0]["stale_fields"] == ["generation"]
    command = logs[0]["command"]
    assert command.startswith('db.runCommand({"collMod": "tsg_service_mappings"')
    assert '"required": ["_id", "tenant_id", "entity_id", "status", "job"]' in command
    assert "generation" not in command


def test_a_stored_validator_that_matches_is_left_alone() -> None:
    server = _RefusingServer(tuple(reversed(MAPPING_FIELDS)))  # the same fields in any order
    assert _start_up(server) == []
    assert server.commands == []


def test_a_validator_that_cannot_be_read_is_a_warning_and_start_up_goes_on() -> None:
    server = _RefusingServer(unreadable=True)
    logs = _start_up(server)
    assert [(line["event"], line["log_level"]) for line in logs] == [
        (LogEvent.MONGODB_VALIDATOR_NOT_APPLIED, "warning")
    ]
    assert server.commands == []
