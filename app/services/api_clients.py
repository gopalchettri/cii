"""API-client use cases: mint (secret shown once), list, revoke, and verify a caller's key."""

import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.constants import ApiClientMessage, ApiKey, AuditAction, AuditTarget, Cache
from app.core.exceptions import Conflict, DuplicateRecord, NotFound
from app.core.singletons import singleton
from app.data_access.admin.repository import ApiClientRepository, api_clients, audit_records
from app.domain.api_keys import could_be_minted_key, hash_api_key
from app.services.audit import admin_actor, audit_target


def _as_client(stored: dict[str, Any]) -> dict[str, Any]:
    """A stored client with its id as `client_id` (`_id` is only MongoDB's name for it)."""
    return {"client_id": stored.pop("_id"), **stored}


class ApiClientService:
    def __init__(self, repository: ApiClientRepository) -> None:
        self._repository = repository
        self._verified: dict[str, tuple[str, float]] = {}  # key hash -> (client id, expiry)

    def mint_api_client(
        self, name: str, description: str | None, created_by: str
    ) -> tuple[dict[str, Any], str]:
        """Create a client and return it with its secret. Only the secret's SHA-256 hash is stored."""
        api_key = ApiKey.PREFIX + secrets.token_urlsafe(ApiKey.RANDOM_BYTES)
        client_id, key_prefix = uuid.uuid4().hex, api_key[: ApiKey.SHOWN_PREFIX_LENGTH]
        client: dict[str, Any] = {
            "client_id": client_id,
            "name": name,
            "description": description,
            "key_hash": hash_api_key(api_key),
            "key_prefix": key_prefix,
            "active": True,
            "created_at": datetime.now(UTC),
            "created_by": created_by,
        }
        stored = {"_id": client_id} | {key: value for key, value in client.items() if key != "client_id"}
        try:
            self._repository.create(stored)
        except DuplicateRecord as exc:  # an active client has its name
            raise Conflict(ApiClientMessage.NAME_TAKEN.format(name=name)) from exc
        client.pop("key_hash")
        audit_records.create_audit_record(
            AuditAction.KEY_MINTED,
            admin_actor(created_by),
            audit_target(AuditTarget.API_CLIENT, client_id),
            after={"name": name, "key_prefix": key_prefix, "active": True},
        )
        return client, api_key

    def list_api_clients(self, active: bool | None) -> list[dict[str, Any]]:
        """Every client (or only active or revoked ones), newest first, never its key hash."""
        where = {} if active is None else {"active": active}
        listed = self._repository.list("without_key_hash", sort="-created_at", **where)
        return [_as_client(stored) for stored in listed]

    def revoke_api_client(self, client_id: str, revoked_by: str) -> dict[str, Any]:
        """Idempotent: revoking a revoked client returns it unchanged; only the first revoke is audited."""
        client = self._repository.revoke_api_client(client_id, revoked_by, datetime.now(UTC))
        if client is not None:
            self._verified.clear()
            audit_records.create_audit_record(
                AuditAction.KEY_REVOKED,
                admin_actor(revoked_by),
                audit_target(AuditTarget.API_CLIENT, client_id),
                before={"active": True},
                after={"active": False},
            )
            return _as_client(client)
        client = self._repository.get("without_key_hash", _id=client_id)
        if client is None:
            raise NotFound(ApiClientMessage.NOT_FOUND.format(client_id=client_id))
        return _as_client(client)

    def find_client_id_for_api_key(self, raw_key: str) -> str | None:
        """The client id owning an active key, or None. Cached per process for Cache.API_KEY_TTL_SECONDS,
        so a revocation reaches every pod within that time. A key that cannot be one TSG minted (wrong prefix
        or length) is refused without a MongoDB read: junk keys from anyone cost nothing."""
        if not could_be_minted_key(raw_key):
            return None
        key_hash = hash_api_key(raw_key)
        cached = self._verified.get(key_hash)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        found = self._repository.get(("_id",), key_hash=key_hash, active=True)
        client_id = found["_id"] if found else None
        # Only real keys are remembered: caching misses would let random wrong keys grow this without end.
        if client_id is not None:
            self._verified[key_hash] = (client_id, time.monotonic() + Cache.API_KEY_TTL_SECONDS)
        return client_id


@singleton
def get_api_client_service() -> ApiClientService:
    return ApiClientService(api_clients)
