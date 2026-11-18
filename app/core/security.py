"""Who is calling (Principal) and the API-key rules: a key is stored by its hash; junk keys cost no read."""

import hashlib
import math
import secrets
from dataclasses import dataclass

from app.core.constants import ApiKey

#: Every minted key: the prefix + secrets.token_urlsafe(RANDOM_BYTES), 4 characters per 3 bytes, no padding.
_MINTED_KEY_LENGTH = len(ApiKey.PREFIX) + math.ceil(ApiKey.RANDOM_BYTES * 4 / 3)


@dataclass(frozen=True)
class Principal:
    client_id: str
    user_id: str
    entity_id: int  # the owning group's id, as in SQL Server (tsg_GetAssetContext @EntityID INT)
    tenant_id: str


def new_api_key() -> str:
    """A new secret key, shown once."""
    return ApiKey.PREFIX + secrets.token_urlsafe(ApiKey.RANDOM_BYTES)


def hash_api_key(raw_key: str) -> str:
    """The SHA-256 hash a key is stored and looked up by."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def could_be_minted_key(raw_key: str) -> bool:
    """True when the key has the prefix and length of a key TSG mints."""
    return raw_key.startswith(ApiKey.PREFIX) and len(raw_key) == _MINTED_KEY_LENGTH
