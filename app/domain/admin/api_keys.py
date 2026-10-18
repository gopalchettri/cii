"""API-key rules: how a key is stored (its hash) and which keys could be one TSG minted."""

import hashlib
import math

from app.core.constants import ApiKey

#: Every minted key: the prefix + secrets.token_urlsafe(RANDOM_BYTES), 4 characters per 3 bytes, no padding.
_MINTED_KEY_LENGTH = len(ApiKey.PREFIX) + math.ceil(ApiKey.RANDOM_BYTES * 4 / 3)


def hash_api_key(raw_key: str) -> str:
    """The SHA-256 hash a key is stored and looked up by."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def could_be_minted_key(raw_key: str) -> bool:
    """True when the key has the prefix and length of a key TSG mints."""
    return raw_key.startswith(ApiKey.PREFIX) and len(raw_key) == _MINTED_KEY_LENGTH
