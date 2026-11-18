"""tsg_api_clients (the API clients, their key hashes, the process's cache of verified keys) and the admin
jobs' queueing."""

import time
import uuid
from collections.abc import Callable
from typing import Any

from pymongo import ReturnDocument
from pymongo.database import Database

from app.core.clock import utc_now
from app.core.constants import ApiClientMessage, ApiKey, Cache, Collection, ConflictReason, ErrorCode, TaskName
from app.core.exceptions import Conflict, DuplicateRecord, NotFound, Unavailable
from app.core.logging import current_request_id
from app.core.security import could_be_minted_key, hash_api_key, new_api_key
from app.crud.admin_jobs import AdminJobRepository
from app.crud.base import MongoRepository

INDEXES = [
    {"keys": "key_hash", "unique": True},
    {"keys": "name", "unique": True, "partialFilterExpression": {"active": True}},
]
_WITHOUT_KEY_HASH = {"key_hash": 0}
_verified: dict[str, tuple[str, float]] = {}  # key hash -> (client id, expiry)


def store(db: Database) -> MongoRepository:
    """tsg_api_clients with its unique indexes, records stamped schema_version 1."""
    return MongoRepository(db[Collection.API_CLIENTS], indexes=INDEXES, schema_version=1)


def _as_client(stored: dict[str, Any]) -> dict[str, Any]:
    return {"client_id": stored.pop("_id"), **stored}


def create_api_client(
    db: Database, name: str, description: str | None, created_by: str | None
) -> tuple[dict[str, Any], str]:
    """A new client (no key hash) and its secret; only the hash is stored. 409 for an active client's name."""
    api_key = new_api_key()
    client_id, key_prefix = uuid.uuid4().hex, api_key[: ApiKey.SHOWN_PREFIX_LENGTH]
    client: dict[str, Any] = {
        "client_id": client_id,
        "name": name,
        "description": description,
        "key_hash": hash_api_key(api_key),
        "key_prefix": key_prefix,
        "active": True,
        "created_at": utc_now(),
        "created_by": created_by,
    }
    stored = {"_id": client_id} | {key: value for key, value in client.items() if key != "client_id"}
    try:
        store(db).create(stored)
    except DuplicateRecord as exc:  # an active client has its name
        raise Conflict(ApiClientMessage.NAME_TAKEN.format(name=name)) from exc
    client.pop("key_hash")
    return client, api_key


def list_api_clients(db: Database, active: bool | None) -> list[dict[str, Any]]:
    """Every client (or only active or revoked ones), newest first, never its key hash."""
    where = {} if active is None else {"active": active}
    listed = db[Collection.API_CLIENTS].find(where, _WITHOUT_KEY_HASH).sort("created_at", -1)
    return [_as_client(stored) for stored in listed]


def revoke_api_client(db: Database, client_id: str, revoked_by: str) -> tuple[dict[str, Any], bool]:
    """The client (no key hash) and whether this call revoked it; 404 for an unknown id."""
    changes = {"active": False, "revoked_at": utc_now(), "revoked_by": revoked_by}
    clients = db[Collection.API_CLIENTS]
    client = clients.find_one_and_update(
        {"_id": client_id, "active": True},
        {"$set": changes},
        projection=_WITHOUT_KEY_HASH,
        return_document=ReturnDocument.AFTER,
    )
    if client is not None:
        _verified.clear()
        return _as_client(client), True
    client = clients.find_one({"_id": client_id}, _WITHOUT_KEY_HASH)
    if client is None:
        raise NotFound(ApiClientMessage.NOT_FOUND.format(client_id=client_id))
    return _as_client(client), False


def get_active_client_id(db: Database, raw_key: str) -> str | None:
    """The active client owning this key, or None; a hit is cached per process for API_KEY_TTL_SECONDS."""
    if not could_be_minted_key(raw_key):
        return None
    key_hash = hash_api_key(raw_key)
    cached = _verified.get(key_hash)
    if cached and cached[1] > time.monotonic():
        return cached[0]
    found = db[Collection.API_CLIENTS].find_one({"key_hash": key_hash, "active": True}, {"_id": 1})
    client_id = found["_id"] if found else None
    # Only real keys are remembered: caching misses would let random wrong keys grow this without end.
    if client_id is not None:
        _verified[key_hash] = (client_id, time.monotonic() + Cache.API_KEY_TTL_SECONDS)
    return client_id


def api_key_still_active(db: Database, raw_key: str) -> bool:
    """True while the key belongs to an active client (a stream's recheck)."""
    return get_active_client_id(db, raw_key) is not None


def queue_admin_job(
    jobs: AdminJobRepository,
    send: Callable[[TaskName, str], bool],
    task: TaskName,
    job: dict[str, Any],
    in_progress: str,
    not_sent: str,
) -> None:
    """Create the queued job and send it: 409 while one of its kind is active; a failed send fails it."""
    job_id = job["_id"]
    active_id = jobs.create_admin_job(job | {"created_at": utc_now(), "request_id": current_request_id()})
    if active_id != job_id:
        raise Conflict(in_progress, reason=ConflictReason.JOB_IN_PROGRESS, details={"job_id": active_id})
    sent = False
    try:
        sent = send(task, job_id)
    finally:
        if not sent:
            error = {"code": ErrorCode.UNAVAILABLE, "message": not_sent}
            jobs.update_admin_job_finished(job_id, utc_now(), error=error)
    if not sent:
        raise Unavailable(not_sent)
