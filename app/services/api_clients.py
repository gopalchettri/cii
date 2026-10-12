"""API-client use cases: mint (secret shown once), list, revoke, and verify a caller's key."""

import hashlib
import math
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.constants import ApiClientMessage, ApiKey, AuditAction, AuditTarget, Cache
from app.core.database import get_mongodb
from app.core.exceptions import NotFound
from app.core.singletons import singleton
from app.data_access.api_clients import ApiClientRepository
from app.services.audit import admin_actor, audit_target, record_audit

#: Every minted key: the prefix + secrets.token_urlsafe(RANDOM_BYTES), 4 characters per 3 bytes, no padding.
_MINTED_KEY_LENGTH = len(ApiKey.PREFIX) + math.ceil(ApiKey.RANDOM_BYTES * 4 / 3)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


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
        self._repository.insert_client(client)
        client.pop("key_hash")
        record_audit(
            AuditAction.KEY_MINTED,
            admin_actor(created_by),
            audit_target(AuditTarget.API_CLIENT, client_id),
            after={"name": name, "key_prefix": key_prefix, "active": True},
        )
        return client, api_key

    def list_api_clients(self, active: bool | None) -> list[dict[str, Any]]:
        return self._repository.list_clients(active)

    def revoke_api_client(self, client_id: str, revoked_by: str) -> dict[str, Any]:
        """Idempotent: revoking a revoked client returns it unchanged; only the first revoke is audited."""
        client = self._repository.revoke_client(client_id, revoked_by, datetime.now(UTC))
        if client is not None:
            self._verified.clear()
            record_audit(
                AuditAction.KEY_REVOKED,
                admin_actor(revoked_by),
                audit_target(AuditTarget.API_CLIENT, client_id),
                before={"active": True},
                after={"active": False},
            )
            return client
        client = self._repository.find_client(client_id)
        if client is None:
            raise NotFound(ApiClientMessage.NOT_FOUND.format(client_id=client_id))
        return client

    def find_client_id_for_api_key(self, raw_key: str) -> str | None:
        """The client id owning an active key, or None. Cached per process for Cache.API_KEY_TTL_SECONDS,
        so a revocation reaches every pod within that time. A key that cannot be one TSG minted (wrong prefix
        or length) is refused without a MongoDB read: junk keys from anyone cost nothing."""
        if not raw_key.startswith(ApiKey.PREFIX) or len(raw_key) != _MINTED_KEY_LENGTH:
            return None
        key_hash = hash_api_key(raw_key)
        cached = self._verified.get(key_hash)
        if cached and cached[1] > time.monotonic():
            return cached[0]
        client_id = self._repository.find_active_client_id_by_key_hash(key_hash)
        # Only real keys are remembered: caching misses would let random wrong keys grow this without end.
        if client_id is not None:
            self._verified[key_hash] = (client_id, time.monotonic() + Cache.API_KEY_TTL_SECONDS)
        return client_id


@singleton
def get_api_client_service() -> ApiClientService:
    return ApiClientService(ApiClientRepository(get_mongodb()))
