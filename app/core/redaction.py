"""Redaction every layer shares: secrets and personal data taken out of free text, secret-named fields masked,
and a bounded preview of any value for the step trace (core/tracing.py). Nothing here returns a secret."""

import dataclasses
import re
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

from app.core.constants import Tracing

_SECRET_PATTERNS = (
    # A PEM private key first, whole, before another pattern can split its body.
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # a JWT
    re.compile(
        r"(?i)\b(?:api[_-]?key|key|(?:\w+[_-])?(?:secret|password|passwd|token))\b\s*(?:=\s*\S+|:\s*.+)"
    ),
    # A URL's user:password (mongodb://user:pw@host, redis://:pw@host): "scheme://[REDACTED]@host".
    re.compile(r"(?<=://)[^\s/@]*:[^\s/@]*(?=@)"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # a cloud access key id
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # a long hex key or hash
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),  # an email address
    re.compile(r"(?i)\b[\w][\w-]*(?:\.[\w-]+)*\.(?:local|internal)\b"),  # an internal host name
)
REDACTED = "[REDACTED]"
MASKED = "***"
#: A field name that holds a secret, or a person's name a log must not keep (a plan's risk owner, BLUEPRINT
#: M11). Whole name parts only: masks api_key, admin_key, access_token, db_dsn and risk_owner, never
#: tokens_in, key_prefix or mitigation_owner (a team, not a person).
SECRET_FIELD_NAME = re.compile(
    r"(^|[_-])(key|secret|password|token|authorization|dsn)$|^risk_owner$", re.IGNORECASE
)


def redact(text: str) -> str:
    """`text` with secrets and personal data replaced by [REDACTED]."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def clipped_text(text: str, limit: int = Tracing.PREVIEW_CHARS) -> str:
    return text if len(text) <= limit else f"{text[:limit]}… (+{len(text) - limit} chars)"


def safe_preview(value: Any, depth: int = 0) -> Any:
    """A bounded, redacted picture of `value` for a log line: text redacted and clipped, secret-named fields
    masked, a long list as its count and first items, a dataclass or model by its fields, anything else by its
    type (an array by its shape). Depth is limited, so a large object never floods a log line."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return clipped_text(redact(value))
    if isinstance(value, bytes | bytearray):
        return f"<{len(value)} bytes>"
    if depth >= Tracing.PREVIEW_DEPTH:
        return f"<{type(value).__name__}>"
    if isinstance(value, Mapping):
        return _preview_mapping(value, depth)
    if isinstance(value, list | tuple | set | frozenset):
        items = list(value)
        shown = [safe_preview(item, depth + 1) for item in items[: Tracing.PREVIEW_ITEMS]]
        return shown if len(items) <= Tracing.PREVIEW_ITEMS else {"count": len(items), "first": shown}
    if isinstance(value, BaseModel):
        return {"type": type(value).__name__, **_preview_mapping(dict(value), depth)}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}
        return {"type": type(value).__name__, **_preview_mapping(fields, depth)}
    shape = getattr(value, "shape", None)
    return f"<{type(value).__name__} {shape}>" if shape is not None else f"<{type(value).__name__}>"


def _preview_mapping(mapping: Mapping[Any, Any], depth: int) -> dict[str, Any]:
    shown: dict[str, Any] = {}
    for position, (key, item) in enumerate(mapping.items()):
        if position == Tracing.PREVIEW_KEYS:
            shown["…"] = f"+{len(mapping) - position} more fields"
            break
        name = str(key)
        shown[name] = MASKED if SECRET_FIELD_NAME.search(name) and item else safe_preview(item, depth + 1)
    return shown
