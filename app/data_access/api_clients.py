"""tsg_api_clients: the only code that reads or writes API clients. A client leaves here with its id as
`client_id`; `_id` is only MongoDB's name for it."""

from datetime import datetime
from typing import Any

from pymongo import ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from app.core.constants import ApiClientMessage, Collection
from app.core.exceptions import Conflict

Doc = dict[str, Any]


_PUBLIC = {"key_hash": 0}


def _as_client(stored: Doc) -> Doc:
    """A stored client with its id as `client_id`."""
    return {"client_id": stored.pop("_id"), **stored}


class ApiClientRepository:
    def __init__(self, db: Database) -> None:
        self._clients = db[Collection.API_CLIENTS]

    def ensure_indexes(self) -> None:
        """Unique key hashes, and unique names among active clients."""
        self._clients.create_index("key_hash", unique=True)
        self._clients.create_index("name", unique=True, partialFilterExpression={"active": True})

    def insert_client(self, client: Doc) -> None:
        """A new client; Conflict when an active client has its name."""
        stored = {"_id": client["client_id"]} | {k: v for k, v in client.items() if k != "client_id"}
        try:
            self._clients.insert_one(stored)
        except DuplicateKeyError as exc:
            raise Conflict(ApiClientMessage.NAME_TAKEN.format(name=client["name"])) from exc

    def list_clients(self, active: bool | None) -> list[Doc]:
        """Every client (or only active or revoked ones), newest first, never its key hash."""
        query = {} if active is None else {"active": active}
        return [_as_client(stored) for stored in self._clients.find(query, _PUBLIC).sort("created_at", -1)]

    def find_active_client_id_by_key_hash(self, key_hash: str) -> str | None:
        """The id of the active client with this key hash."""
        found = self._clients.find_one({"key_hash": key_hash, "active": True}, {"_id": 1})
        return found["_id"] if found else None

    def find_client(self, client_id: str) -> Doc | None:
        """One client, never its key hash."""
        stored = self._clients.find_one({"_id": client_id}, _PUBLIC)
        return _as_client(stored) if stored else None

    def revoke_client(self, client_id: str, revoked_by: str, revoked_at: datetime) -> Doc | None:
        """Deactivate an active client and return it; None when there was no active client to revoke."""
        stored = self._clients.find_one_and_update(
            {"_id": client_id, "active": True},
            {"$set": {"active": False, "revoked_at": revoked_at, "revoked_by": revoked_by}},
            projection=_PUBLIC,
            return_document=ReturnDocument.AFTER,
        )
        return _as_client(stored) if stored else None
