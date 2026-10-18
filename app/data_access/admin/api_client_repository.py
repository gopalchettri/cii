"""tsg_api_clients: the API clients, their key hashes, and the process's cache of verified keys."""

import time
from collections.abc import Callable
from datetime import datetime

from pymongo.collection import Collection as MongoCollection

from app.core.constants import Cache, Collection
from app.data_access.base import MongoRepository, Record


class ApiClientRepository(MongoRepository):
    """tsg_api_clients: unique key hashes, unique names among active clients."""

    def __init__(
        self,
        collection: str | MongoCollection = Collection.API_CLIENTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """tsg_api_clients with its unique indexes, and an empty cache of verified keys."""
        super().__init__(
            collection,
            indexes=[
                {"keys": "key_hash", "unique": True},
                {"keys": "name", "unique": True, "partialFilterExpression": {"active": True}},
            ],
            field_lists={"without_key_hash": {"key_hash": 0}},
            schema_version=1,
        )
        self._clock = clock
        self._verified: dict[str, tuple[str, float]] = {}  # key hash -> (client id, expiry)

    def revoke_api_client(self, client_id: str, revoked_by: str, revoked_at: datetime) -> Record | None:
        """Deactivates the active tsg_api_clients client and returns it (no key hash), and forgets every
        verified key; None when no active client has that id."""
        changes = {"active": False, "revoked_at": revoked_at, "revoked_by": revoked_by}
        client = self.update_and_get(changes, fields="without_key_hash", _id=client_id, active=True)
        if client is not None:
            self._verified.clear()
        return client

    def get_active_client_id(self, key_hash: str) -> str | None:
        """The id of the active client with this key hash, or None. Cached per process for
        Cache.API_KEY_TTL_SECONDS, so a revocation reaches every pod within that time."""
        cached = self._verified.get(key_hash)
        if cached and cached[1] > self._clock():
            return cached[0]
        found = self.get(("_id",), key_hash=key_hash, active=True)
        client_id = found["_id"] if found else None
        # Only real keys are remembered: caching misses would let random wrong keys grow this without end.
        if client_id is not None:
            self._verified[key_hash] = (client_id, self._clock() + Cache.API_KEY_TTL_SECONDS)
        return client_id
