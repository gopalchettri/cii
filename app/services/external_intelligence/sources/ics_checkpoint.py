"""The checkpoint of the CISA ICS advisories: the change time everything before is done, and the advisory
files that failed to download so far with how many runs each has failed.

Format: `<change time>` or `<change time>|<path>=<runs>;<path>=<runs>`, e.g.
`2026-10-12T01:39:00.000000Z|2025/icsa-25-100-01.json=2;2025/icsa-25-101-03.json=1`.
The change time is the last one BEFORE the first file that failed, so a file that failed once is read again
at the next run (see cisa_ics_advisories_source.py). The list is bounded, so the checkpoint stays small."""

import re
from datetime import UTC, datetime

from app.core.constants import IcsReading

_ENTRY = re.compile(r"(\d{4}/[\w.-]+\.json)=(\d{1,2})")
_STAMP = re.compile(r"\d{4}-\d\d-\d\dT[\d:.]+Z")


def is_past(stamp: str, now: datetime) -> bool:
    """True when `stamp` is a change time in the format that is not later than `now`."""
    if not _STAMP.fullmatch(stamp):
        return False
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")) <= now.astimezone(UTC)
    except ValueError:
        return False


def parse_checkpoint(checkpoint: str | None, now: datetime) -> tuple[str | None, dict[str, int]]:
    """(change time, {path: failed runs}); anything not in the format, or with a change time after `now`
    (a checkpoint saved before this rule, which would stall the source for ever), starts a first run."""
    stamp, _, failed = (checkpoint or "").partition("|")
    entries = (_ENTRY.fullmatch(part) for part in failed.split(";") if part)
    counts = {match[1]: int(match[2]) for match in entries if match}
    return (stamp if is_past(stamp, now) else None), counts


def format_checkpoint(stamp: str, failed: dict[str, int]) -> str:
    """The checkpoint string; at most IcsReading.MAX_FAILED_FILES failed files are remembered."""
    if not failed:
        return stamp
    kept = list(failed.items())[: IcsReading.MAX_FAILED_FILES]
    return stamp + "|" + ";".join(f"{path}={runs}" for path, runs in kept)
