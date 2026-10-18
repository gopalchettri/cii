"""Redaction every layer shares: secrets and personal data taken out of free text, secret-named fields masked.
Nothing here returns a secret."""

import re

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


def clipped_text(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}… (+{len(text) - limit} chars)"
