"""MongoRepository: every plain read and write of one MongoDB collection, done once. Callers pass field
equality as keywords and the repository's named conditions (name=True, or name=value for a condition that
takes one); a repository adds a named method only for a real rule (a lease, a guarded state change, an
aggregate). No timeout here: the records that need one keep their own. Every write waits for a majority
(the client's write concern, app/core/database.py)."""

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

import structlog
from pymongo import ReplaceOne, ReturnDocument
from pymongo.collection import Collection as MongoCollection
from pymongo.errors import BulkWriteError, DuplicateKeyError, OperationFailure, PyMongoError

from app.core.constants import ErrorMessage, LogEvent
from app.core.database import expire_documents_after, get_mongodb
from app.core.exceptions import DuplicateRecord

Record = dict[str, Any]
#: A named condition: a filter applied when the caller passes name=True, or built from the value passed.
Condition = Mapping[str, Any] | Callable[[Any], Mapping[str, Any]]

_DUPLICATE_KEY = 11000  # MongoDB's error code for a value a unique index already holds
_INDEX_NOT_FOUND = 27  # MongoDB's error code for dropping an index that is not there
_INDEX_NAME_IN_ERROR = re.compile(r"index: (\S+)")
#: The field create and save stamp with the record shape version; a record without it is version 1.
SCHEMA_VERSION_FIELD = "schema_version"

log = structlog.get_logger(__name__)


def duplicate_index_name(error: DuplicateKeyError) -> str:
    """The name of the unique index that refused a write, read from MongoDB's error."""
    details = error.details or {}
    found = _INDEX_NAME_IN_ERROR.search(details.get("errmsg", "") or str(error))
    return found.group(1) if found else "_".join(details.get("keyPattern", {})) or "unknown"


def _sort_spec(sort: str | Iterable[str] | None) -> list[tuple[str, int]] | None:
    """'-created_at' or ['-score', 'title'] as pymongo's sort: a leading '-' sorts newest or largest first."""
    if sort is None:
        return None
    names = [sort] if isinstance(sort, str) else list(sort)
    return [(name[1:], -1) if name.startswith("-") else (name, 1) for name in names]


def _merged(parts: Iterable[Mapping[str, Any]]) -> Record:
    """Filter parts as one filter; a field two parts both name goes in $and, so neither part is dropped."""
    merged: Record = {}
    clashing: list[Record] = []
    for part in parts:
        for key, value in part.items():
            if key in merged:
                clashing.append({key: value})
            else:
                merged[key] = value
    if clashing:
        merged["$and"] = [*merged.get("$and", []), *clashing]
    return merged


class MongoRepository:
    """One MongoDB collection: its indexes, expiries, named conditions, field lists, reads and writes."""

    def __init__(
        self,
        collection: str | MongoCollection,
        indexes: Iterable[Mapping[str, Any]] = (),
        ttl: Iterable[tuple[str, int | Callable[[], int]]] = (),
        conditions: Mapping[str, Condition] | None = None,
        field_lists: Mapping[str, Iterable[str] | Mapping[str, int]] | None = None,
        required: Iterable[str] = (),
        schema_version: int = 1,
    ) -> None:
        """`collection`: its name (resolved on first use, never at import) or a pymongo Collection (tests,
        the job lease). `indexes`: create_index keywords. `ttl`: (field, seconds or a function) per expiry.
        `required`: what the validator asks of a record. `schema_version`: stamped by each create and save."""
        self._collection = collection
        self._indexes, self._ttl = tuple(indexes), tuple(ttl)
        self._conditions, self._field_lists = dict(conditions or {}), dict(field_lists or {})
        self._required, self._stamp = tuple(required), {SCHEMA_VERSION_FIELD: schema_version}

    @property
    def collection(self) -> MongoCollection:
        """The pymongo collection, for this repository's own rule methods inside app/data_access."""
        if isinstance(self._collection, str):
            return get_mongodb()[self._collection]
        return self._collection

    def create_indexes(self) -> None:
        """The collection's validator, every index and TTL expiry; idempotent, run at start-up."""
        _apply_validator(self.collection, self._required)
        for index in self._indexes:
            self.collection.create_index(**index)
        for field, seconds in self._ttl:
            expire_documents_after(self.collection, field, seconds() if callable(seconds) else seconds)

    def create(self, record: Record) -> Any:
        """Inserts a new record, returns its _id; DuplicateRecord names the unique index that refused it."""
        try:
            return self.collection.insert_one(record | self._stamp).inserted_id
        except DuplicateKeyError as error:
            raise DuplicateRecord(duplicate_index_name(error)) from error

    def save(self, record: Record, only_if: Mapping[str, Any] | None = None) -> bool:
        """Inserts the record, or replaces the one with its _id while `only_if` matches it. False when a
        record with that _id exists that may not be replaced; DuplicateRecord for any other unique index."""
        query = self.filter({"_id": record["_id"], **(only_if or {})})
        try:
            self.collection.replace_one(query, record | self._stamp, upsert=True)
        except DuplicateKeyError as error:
            index_name = duplicate_index_name(error)
            if index_name == "_id_":
                return False
            raise DuplicateRecord(index_name) from error
        return True

    def get(self, fields: str | Iterable[str] | None = None, **where: Any) -> Record | None:
        """The first record matching `where` (only `fields`, a field list's name or the fields), or None."""
        return self.collection.find_one(self.filter(where), _projection(self._field_lists, fields))

    def list(
        self,
        fields: str | Iterable[str] | None = None,
        sort: str | Iterable[str] | None = None,
        skip: int = 0,
        limit: int = 0,
        **where: Any,
    ) -> list[Record]:
        """Every record matching `where`, sorted ('-field' for descending), after `skip`, at most `limit`."""
        cursor = self.collection.find(
            self.filter(where), _projection(self._field_lists, fields), skip=skip, limit=limit
        )
        spec = _sort_spec(sort)
        return list(cursor.sort(spec) if spec else cursor)

    def count(self, **where: Any) -> int:
        """How many records match `where`."""
        return self.collection.count_documents(self.filter(where))

    def update(
        self,
        changes: Mapping[str, Any],
        *,
        only_if: Mapping[str, Any] | None = None,
        many: bool = False,
        **where: Any,
    ) -> int:
        """Sets `changes` on the record (or every record, `many`) matching `where` and `only_if`; how many
        matched. An update document with $ operators is passed only from inside app/data_access."""
        query = self._required_filter({**where, **(only_if or {})})
        write = self.collection.update_many if many else self.collection.update_one
        return write(query, _update_document(changes)).matched_count

    def update_and_get(
        self,
        changes: Mapping[str, Any],
        *,
        sort: str | Iterable[str] | None = None,
        fields: str | Iterable[str] | None = None,
        **where: Any,
    ) -> Record | None:
        """Sets `changes` on the first record matching `where` (in `sort` order) and returns it as changed."""
        return self.collection.find_one_and_update(
            self._required_filter(where),
            _update_document(changes),
            projection=_projection(self._field_lists, fields),
            sort=_sort_spec(sort),
            return_document=ReturnDocument.AFTER,
        )

    def delete(self, **where: Any) -> int:
        """Deletes every record matching `where`; how many went. An empty `where` is refused."""
        return self.collection.delete_many(self._required_filter(where)).deleted_count

    def bulk_write_skipping_duplicates(self, operations: Sequence[Any], *, ordered: bool = True) -> Record:
        """Runs pymongo write operations in one bulk write; a duplicate key is skipped (an ordered write stops
        there), any other write error or a write-concern error is raised. MongoDB's counts (nInserted ...)."""
        if not operations:
            return {}
        try:
            return self.collection.bulk_write(operations, ordered=ordered).bulk_api_result
        except BulkWriteError as error:
            details = error.details
            refused = [
                found for found in details.get("writeErrors", []) if found.get("code") != _DUPLICATE_KEY
            ]
            if refused or details.get("writeConcernErrors"):
                raise
            return dict(details)

    def filter(self, where: Mapping[str, Any]) -> Record:
        """`where` as a MongoDB filter: field equality and each named condition (name=True or a value)."""
        return _merged(self._condition(name, value) for name, value in where.items())

    def _condition(self, name: str, value: Any) -> Mapping[str, Any]:
        """One `where` entry as a filter part: a named condition, or plain field equality."""
        if name not in self._conditions:
            return {name: value}
        condition = self._conditions[name]
        if callable(condition):
            return condition(value)
        if value is not True:  # a fixed condition is a guard: never silently dropped by name=False
            raise ValueError(ErrorMessage.NAMED_CONDITION_TAKES_TRUE.format(name=name))
        return condition

    def _required_filter(self, where: Mapping[str, Any]) -> Record:
        """`where` as a filter for a write; an empty one is refused."""
        if not where:  # a write with no condition would change or delete the whole collection
            raise ValueError(ErrorMessage.WRITE_NEEDS_A_CONDITION)
        return self.filter(where)


def _projection(
    field_lists: Mapping[str, Any], fields: str | Iterable[str] | Mapping[str, int] | None
) -> Mapping[str, int] | None:
    """A field list's name, the fields themselves or a projection, as pymongo's projection (None: all)."""
    if fields is None:
        return None
    if isinstance(fields, str):
        fields = field_lists[fields]
    projection = fields if isinstance(fields, Mapping) else dict.fromkeys(fields, 1)
    if projection and not any(projection.values()):  # an exclusion: what callers show stays as it was
        return {**projection, SCHEMA_VERSION_FIELD: 0}
    return projection


def _update_document(changes: Mapping[str, Any]) -> Mapping[str, Any]:
    """Plain fields go in $set; a document of $ operators is used as it is."""
    return changes if any(key.startswith("$") for key in changes) else {"$set": dict(changes)}


def drop_retired_index(collection: MongoCollection, name: str) -> None:
    """Drops the retired index `name`; none of that name (never built, or another process starting now
    dropped it) and no collection yet are fine."""
    try:
        collection.drop_index(name)
    except OperationFailure as exc:
        if exc.code != _INDEX_NOT_FOUND:
            raise


def _apply_validator(collection: MongoCollection, required: Sequence[str]) -> None:
    """A $jsonSchema validator refusing a new or changed record without a `required` field: collMod on an
    existing collection, else the collection created with it; a server or user refusing it is logged."""
    if not required:
        return
    options: Record = {
        "validator": {"$jsonSchema": {"bsonType": "object", "required": list(required)}},
        "validationLevel": "moderate",  # records stored invalid before stay writable
        "validationAction": "error",
    }
    database, name = collection.database, collection.name
    try:
        if database.list_collection_names(filter={"name": name}):
            database.command("collMod", name, **options)
        else:
            database.create_collection(name, **options)
    except PyMongoError as error:  # an older server or no collMod right: start-up goes on without it
        log.warning(LogEvent.MONGODB_VALIDATOR_NOT_APPLIED, collection=name, error=str(error))


class VectorRepository(MongoRepository):
    """A vector collection, each vector stored by its key as _id and expiring at its own expires_at (a query
    vector always, a library vector once retired); `ids=keys` finds the vectors with those keys."""

    def __init__(
        self,
        collection: str | MongoCollection,
        conditions: Mapping[str, Condition] | None = None,
        **options: Any,
    ) -> None:
        """The vector collection with its expiry, its `ids` condition and any other `conditions`."""
        conditions = {"ids": _vector_ids, **(conditions or {})}
        super().__init__(collection, ttl=[("expires_at", 0)], conditions=conditions, **options)

    def save_vectors(self, vectors: list[Record]) -> None:
        """Writes each vector whole (one of the wrong size is replaced). Another worker storing the same text
        at the same moment is fine (an identical vector); any other write error is raised."""
        upserts = [ReplaceOne({"_id": vector["_id"]}, vector, upsert=True) for vector in vectors]
        self.bulk_write_skipping_duplicates(upserts, ordered=False)


def _vector_ids(keys: Iterable[str]) -> Record:
    """The vectors with these keys."""
    return {"_id": {"$in": list(set(keys))}}
