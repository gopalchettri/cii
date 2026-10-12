"""What never reaches an AI model (v1 core/security.py and prompts._scrub_db_keys, ported as they are):
secrets and personal data in free text, empty or placeholder facts, and database ids."""

from typing import Any

from app.core.redaction import REDACTED, redact

__all__ = ["REDACTED", "redact", "facts_safe_for_prompt", "drop_database_ids", "DATABASE_KEYS"]

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


def _redacted(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redacted(item) for item in value]
    if isinstance(value, dict):
        return {key: _redacted(item) for key, item in value.items()}
    return value


def _carries_a_fact(value: Any) -> bool:
    return not (
        isinstance(value, str) and (not value.strip() or value.strip().casefold() in _PLACEHOLDER_VALUES)
    )


def drop_database_ids(value: Any) -> Any:
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
