"""The AI usage runbook's commands, run in any app pod (the image holds app/ only):

python -m app.worker.admin.ai_usage_tools copy-texts
    after the first release with AI usage: the previous release's AI call texts (tsg_ai_calls, expired
    after 14 days) copied into tsg_ai_call_texts, kept for good, a day at a time; safe to run again.
python -m app.worker.admin.ai_usage_tools roll-up SINCE UNTIL
    every UTC hour from SINCE to UNTIL (ISO, e.g. 2026-10-01T00:00+00:00) added up again.
python -m app.worker.admin.ai_usage_tools replay FILE
    the rows of the ai.usage_row_spilled lines in FILE ("-" reads standard input) stored, then every hour
    from the oldest one to now added up again; safe to run again. FILE is what Loki gives: Grafana Explore's
    JSON download (one array), its text download (a time before each line), logcli's raw lines, or TSG's own
    JSON lines; in UTF-8 or UTF-16 (a PowerShell redirect)."""

import json
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from bson import ObjectId

from app.core.clock import utc_now
from app.core.constants import PREVIOUS_AI_CALL_TEXTS, AiUsageLogEvent


def spilled_rows(text: str) -> list[dict[str, Any]]:
    """Each spilled row the exported text holds, its ids and time turned back from text (the log keeps them
    as text); anything else in it is skipped."""
    rows = []
    for entry in _log_entries(text):
        if entry.get("event") != AiUsageLogEvent.ROW_SPILLED or not isinstance(entry.get("row"), dict):
            continue
        row = dict(entry["row"])
        row["_id"] = ObjectId(row["_id"])
        if row.get("ask_id"):
            row["ask_id"] = ObjectId(row["ask_id"])
        row["created_at"] = datetime.fromisoformat(row["created_at"])
        rows.append(row)
    return rows


def _log_entries(text: str) -> Iterator[dict[str, Any]]:
    """TSG's log lines in an export: Grafana's JSON array of {line, ...}, or one line each, maybe after a
    time (Grafana's text download) or under "line" (Loki's own export)."""
    stripped = text.lstrip()
    lines: Iterable[Any] = json.loads(stripped) if stripped.startswith("[") else stripped.splitlines()
    for item in lines:
        entry = _json_object(item) if isinstance(item, str) else item
        if isinstance(entry, dict) and isinstance(entry.get("line"), str):
            entry = _json_object(entry["line"])
        if isinstance(entry, dict):
            yield entry


def _json_object(line: str) -> Any:
    """The JSON object a text line holds from its first "{" on; None when it holds none."""
    _, brace, rest = line.partition("{")
    try:
        return json.loads(brace + rest) if brace else None
    except ValueError:
        return None


def replay_spilled_rows(text: str) -> int:
    """Stores the spilled rows (one already stored is skipped) and adds up every hour from the oldest one to
    now, both under the add-up's lock (no row is stored without its hours added up), so a request counted in
    a later hour while its first rows were missing is counted once, in its first; how many rows there were."""
    from app.container import get_ai_usage_service

    rows = spilled_rows(text)
    if rows:
        get_ai_usage_service().replay_rows(rows, min(row["created_at"] for row in rows), utc_now())
    return len(rows)


def _read_export(name: str) -> str:
    """The exported file's text ("-": standard input), whether UTF-8 (with or without its mark) or UTF-16."""
    data = sys.stdin.buffer.read() if name == "-" else Path(name).read_bytes()
    return data.decode("utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig")


def main(command: str, *arguments: str) -> str:
    """Runs one command; what it did, in one line."""
    from app.container import get_ai_call_repository, get_ai_usage_service

    if command == "copy-texts":
        held = get_ai_call_repository().copy_records_from(PREVIOUS_AI_CALL_TEXTS)
        return f"tsg_ai_call_texts now holds {held} AI call texts (copied from {PREVIOUS_AI_CALL_TEXTS})."
    if command == "roll-up":
        since, until = (datetime.fromisoformat(argument) for argument in arguments[:2])
        return f"{get_ai_usage_service().roll_up_hours(since, until)} hours of AI usage added up again."
    if command == "replay":
        stored = replay_spilled_rows(_read_export(arguments[0]))
        return f"{stored} spilled AI usage rows stored (any already stored skipped)."
    return __doc__ or ""


def run(arguments: list[str]) -> int:
    """Runs one command line: its answer printed (exit code 0), or why it could not run, such as the add-up's
    lock not being free or MongoDB too slow, in one line, not a traceback (exit code 1)."""
    from app.core.constants import AiUsageMessage
    from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Unavailable

    try:
        print(main(*arguments))  # noqa: T201 - a command-line tool's answer
    except Unavailable as busy:
        print(busy.detail, file=sys.stderr)  # noqa: T201
        return 1
    except MONGO_UNAVAILABLE_ERRORS as slow:
        print(AiUsageMessage.MONGO_TOO_SLOW.format(error=type(slow).__name__), file=sys.stderr)  # noqa: T201
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
