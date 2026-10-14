"""Is a product version inside an advisory's affected ranges? A small, conservative comparator.

Only dotted numbers (2.3, 10.0.1) with an optional simple suffix are understood: a pre-release (alpha, beta,
rc, a, b) sorts before the release, a patch (sp, p, patch, update, u) after it. Anything else, a flag that is
not true / false, or a fixed version that cannot be read is "not known" (None): the answer is never guessed,
and nothing in here raises on malformed data. A range with both bounds stated as none means every version; a
missing start_inclusive means True."""

import re
from typing import Any

from app.core.constants import TextCleaning

#: (numbers without trailing zeros, suffix rank, suffix number): tuples compare in the right order.
Key = tuple[tuple[int, ...], int, int]

_VERSION = re.compile(
    r"^v?(\d+(?:\.\d+)*)(?:[-_.\s]?(alpha|beta|patch|update|rc|sp|a|b|p|u)[-_.]?(\d*))?$", re.IGNORECASE
)
_SUFFIX_RANK = {"alpha": -3, "a": -3, "beta": -2, "b": -2, "rc": -1}  # any other suffix is a patch: 1


def parse(value: Any) -> Key | None:
    """The comparable form of a version, or None when it is not certainly one of the supported forms."""
    if not isinstance(value, str) or not value.strip() or len(value) > TextCleaning.VERSION_CHARS:
        return None
    found = _VERSION.match(value.strip())
    if found is None:
        return None
    numbers = [int(part) for part in found.group(1).split(".")]
    while numbers and numbers[-1] == 0:
        numbers.pop()
    suffix = (found.group(2) or "").casefold()
    rank = _SUFFIX_RANK.get(suffix, 1) if suffix else 0
    return tuple(numbers), rank, int(found.group(3) or 0)


def _compare(left: Key, right: Key) -> int:
    return (left > right) - (left < right)


def _in_range(target: Key, version_range: Any) -> bool | None:
    """True / False when the range is read with certainty; None otherwise."""
    if not isinstance(version_range, dict):
        return None
    start, end = version_range.get("start"), version_range.get("end")
    if start is None and end is None:  # both bounds stated as none: every version; absent keys: not stated
        return True if {"start", "end"} <= version_range.keys() else None
    inside = True
    for bound, inclusive, direction in (
        (start, version_range.get("start_inclusive", True), 1),  # a start that says nothing is inclusive
        (end, version_range.get("end_inclusive"), -1),
    ):
        if bound is None:
            continue
        key = parse(bound)
        if key is None or not isinstance(inclusive, bool):
            return None
        gap = _compare(target, key) * direction  # negative: the wrong side of this bound
        inside = inside and (gap > 0 or (gap == 0 and inclusive))
    return inside


def _reaches_fix(target: Key, fixed: list[Any]) -> bool | None:
    """True when the version is at or after a fixed version; None when a fixed version cannot be read."""
    keys = [parse(item) for item in fixed]
    if any(key is not None and _compare(target, key) >= 0 for key in keys):
        return True
    return None if any(key is None for key in keys) else False


def affected_state(version: Any, entry: dict[str, Any]) -> bool | None:
    """Whether `version` is affected by one advisory entry ({versions: [...], fixed: [...]}): True, False, or
    None when that cannot be said for certain. Inside a range but at or after a fixed version is a record
    that contradicts itself (a fix on another branch, say): None, never a guess."""
    target, ranges, fixed = parse(version), entry.get("versions"), entry.get("fixed") or []
    if target is None or not isinstance(ranges, list) or not ranges or not isinstance(fixed, list):
        return None  # no version, or the record does not state which versions
    states = [_in_range(target, version_range) for version_range in ranges]
    if any(state is True for state in states):
        return True if _reaches_fix(target, fixed) is False else None
    return None if any(state is None for state in states) else False
