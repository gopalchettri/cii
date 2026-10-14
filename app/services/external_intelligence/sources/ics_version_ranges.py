"""Version wording of a CSAF product branch, as plain ranges. Deterministic and strict: wording that is not
understood gives no ranges (the caller keeps the raw text), never a guess. A range is
{start, end, end_inclusive}; start None is "from the first version", end None is "to the last"."""

import re

_ALL = re.compile(r"\*|all( versions?)?", re.IGNORECASE)
_SPLIT = re.compile(r"[|,]|\band\b")
_TOKEN = re.compile(r"(<=|>=|!=|<|>|=)?\s*[vV]?(\d[\w.+-]*)")


def parse_versions(name: str) -> list[dict[str, str | bool | None]]:
    """Ranges for "vers:scheme/>=1|<2", "<=1.4", ">= 1.0, < 2.0", "3.5|3.0", "2.1" or "all versions";
    [] when the wording is anything else (a name such as "<=Firmware_3.11", an exclusive start, "!=")."""
    text = name.strip()
    if text.lower().startswith("vers:"):
        text = text[5:].partition("/")[2]
    if _ALL.fullmatch(text):
        return [_range(None, None, False)]
    ranges: list[dict[str, str | bool | None]] = []
    start: str | None = None
    for part in _SPLIT.split(text):
        token = _TOKEN.fullmatch(part.strip())
        if token is None:
            return []
        op, version = token.groups()
        if op in (None, "="):
            _flush(ranges, start)
            start = None
            ranges.append(_range(version, version, True))
        elif op == ">=":
            _flush(ranges, start)
            start = version
        elif op in ("<", "<="):
            ranges.append(_range(start, version, op == "<="))
            start = None
        else:  # ">" and "!=" cannot be said with an inclusive start
            return []
    _flush(ranges, start)
    return ranges


def _flush(ranges: list[dict[str, str | bool | None]], start: str | None) -> None:
    """A lower bound still waiting for its upper bound is open-ended."""
    if start is not None:
        ranges.append(_range(start, None, False))
    return None


def _range(start: str | None, end: str | None, end_inclusive: bool) -> dict[str, str | bool | None]:
    return {"start": start, "end": end, "end_inclusive": end_inclusive}
