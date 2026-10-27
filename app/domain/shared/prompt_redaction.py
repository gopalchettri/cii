"""What never reaches an AI model: secrets and personal data in free text, empty or placeholder facts,
database ids and code's platform note."""

import re
from typing import Any

from app.core.constants import Writing
from app.core.redaction import redact

#: Dropdown labels and filler that carry no fact ("NA" is a real option in the platform's lists).
_PLACEHOLDER_VALUES = frozenset(
    {
        "na",
        "n/a",
        "n.a.",
        "n.a",
        "not applicable",
        "none",
        "nil",
        "null",
        "-",
        "--",
        "tbd",
        "to be determined",
        "unknown",
        "not available",
    }
)
#: Keys that hold a database id or an internal field: never in a prompt, at any depth.
DATABASE_KEYS = frozenset(
    {
        "id",
        "alias",
        "criticality",
        "category_id",
        "category_code",
        "type_id",
        "catalogue_id",
        "actor_id",
        "control_id",
    }
)
#: Code's platform note on a shown assumption, with any punctuation or space before it, in any case.
_PLATFORM_NOTE = re.compile(r"\W*" + re.escape(Writing.PLATFORM_NOTE.removeprefix(" - ")), re.IGNORECASE)


def without_platform_note(text: str) -> str:
    """`text` without code's platform note: the AI never reads it, so never writes it."""
    return _PLATFORM_NOTE.sub("", text)


def _redacted(value: Any) -> Any:
    """Every text in `value`, at any depth, redacted."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    return value


def _carries_a_fact(value: Any) -> bool:
    """False for a blank or placeholder text ("N/A", "tbd")."""
    return not (
        isinstance(value, str) and (not value.strip() or value.strip().casefold() in _PLACEHOLDER_VALUES)
    )


def drop_database_ids(value: Any) -> Any:
    """`value` without database ids and internal keys, at any depth."""
    if isinstance(value, dict):
        return {key: drop_database_ids(item) for key, item in value.items() if key not in DATABASE_KEYS}
    if isinstance(value, list | tuple):
        return [drop_database_ids(item) for item in value]
    return value


def facts_safe_for_prompt(facts: dict[str, Any]) -> dict[str, Any]:
    """`facts` as a prompt may carry them: database keys dropped, free text redacted, and every fact with no
    value left out (None, blank, an empty list, a placeholder such as "N/A"), so the model reads "unknown"
    rather than "none". 0 and False are facts and stay."""
    kept: dict[str, Any] = {}
    for name, value in drop_database_ids(facts).items():
        if (
            value is None
            or (isinstance(value, str | list | dict) and not value)
            or not _carries_a_fact(value)
        ):
            continue
        if isinstance(value, list):
            value = [item for item in value if _carries_a_fact(item)]
            if not value:
                continue
        kept[name] = _redacted(value)
    return kept
