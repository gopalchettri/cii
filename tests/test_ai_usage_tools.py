"""The AI usage runbook's commands (python -m app.worker.admin.ai_usage_tools, run in an app pod): a usage row
MongoDB did not take, logged whole, is stored again exactly from whatever Loki export an operator has
(replay), and the previous release's AI call texts are carried into the collection that keeps them for good
(copy-texts). Both safe to run twice."""

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from bson import ObjectId
from pymongo.errors import ExecutionTimeout
from structlog.testing import capture_logs

from app.ai.attempts import write_usage_rows
from app.core.clock import utc_now
from app.core.constants import AiUsageCollection, AiUsageMessage
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.admin.ai_call_repository import AiCallRepository
from app.data_access.admin.ai_usage_repository import AiUsageRepository
from app.worker.admin import ai_usage_tools


def _spilled(rows: list[dict], monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """The log entries MongoDB refusing these rows leaves, as structlog renders them."""

    def refused(*_: object) -> None:
        raise ConnectionError("mongodb down")

    with monkeypatch.context() as down:
        down.setattr(AiUsageRepository, "create_rows", refused)
        with capture_logs() as logs:
            write_usage_rows([dict(row) for row in rows])
    return logs


def _row(request_id: str, at: datetime, **extra: object) -> dict:
    fields = {"bucket": "threats", "task": "relevance_gate", "model": "kimi", "outcome": "ok", "try_no": 1}
    return {
        "_id": ObjectId(),
        "created_at": at,
        "request_id": request_id,
        "ask_id": ObjectId(),
        **fields,
        **extra,
    }


def test_a_spilled_row_is_stored_again_exactly_and_only_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The log keeps ids and times as text; the replay turns them back, so the row is the one that would have
    been stored (an id as text would never match its ask, a time as text never falls in an hour). Mutation:
    store `created_at` as text."""
    request_id = uuid.uuid4().hex
    row = _row(request_id, utc_now().replace(microsecond=123000) - timedelta(hours=1))
    lines = [json.dumps(entry, default=str) for entry in _spilled([row], monkeypatch)]  # TSG's JSON lines
    assert ai_usage_tools.replay_spilled_rows("\n".join(lines)) == 1
    assert ai_usage_tools.replay_spilled_rows("\n".join(lines)) == 1  # again: already stored, nothing doubles
    [stored] = get_mongodb()[AiUsageCollection.USAGE].find({"request_id": request_id})
    assert {name: stored[name] for name in row} == row


def test_replay_reads_each_export_an_operator_has(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Review 2026-10-29: replay read JSON lines only, but Grafana Explore downloads one JSON array (or a text
    file with a time before each line) and a PowerShell redirect writes UTF-16: nothing was stored and the
    rows were lost once Loki dropped them. Mutation: read the file line by line as UTF-8 again."""
    rows = [_row(uuid.uuid4().hex, datetime(2025, 5, 2, 7, tzinfo=UTC)) for _ in range(3)]
    lines = [json.dumps(entry, default=str) for entry in _spilled(rows, monkeypatch)]
    grafana_json = json.dumps([{"line": lines[0], "timestamp": "1746169200000", "fields": {}}])
    grafana_text = f"2025-05-02 07:00:01.000\t{lines[1]}\nnot a log line\n"
    utf16 = (tmp_path / "spilled.txt").open("w", encoding="utf-16")
    utf16.write(lines[2] + "\n")
    utf16.close()
    found = [
        ai_usage_tools.spilled_rows(grafana_json),
        ai_usage_tools.spilled_rows(grafana_text),
        ai_usage_tools.spilled_rows(ai_usage_tools._read_export(str(tmp_path / "spilled.txt"))),
    ]
    assert [[row["request_id"] for row in rows_found] for rows_found in found] == [
        [row["request_id"]] for row in rows
    ]


def test_a_replay_counts_a_request_once_in_the_hour_of_its_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review 2026-10-29: a request whose first rows were spilled was counted in the hour of its first stored
    row; the replay added up only the replayed hour, so it was counted there too. It now adds up every hour
    from the oldest row to now. Mutation: add up only the replayed rows' hours."""
    from app import container

    request_id, now = uuid.uuid4().hex, utc_now()
    first, later = now - timedelta(hours=2), now - timedelta(hours=1)
    marker = f"replay-{uuid.uuid4().hex}"
    AiUsageRepository().create_rows([_row(request_id, later, model=marker)])
    container.get_ai_usage_service().roll_up_hours(first, now)
    spilled = _spilled([_row(request_id, first, model=marker)], monkeypatch)
    ai_usage_tools.replay_spilled_rows("\n".join(json.dumps(entry, default=str) for entry in spilled))
    hourly = get_mongodb()[AiUsageCollection.HOURLY].find({"model": marker})
    counted = {doc["hour"]: doc["requests"] for doc in hourly}
    assert sum(counted.values()) == 1 and counted[first.replace(minute=0, second=0, microsecond=0)] == 1


def test_the_previous_releases_call_texts_are_carried_over_once() -> None:
    """A day at a time (one copy of it all outlasted the client's 30 s wait, review 2026-10-29), a record with
    no time too. Mutation: replace a text already carried over (a newer copy would be lost)."""
    old = get_mongodb()[f"test_old_calls_{uuid.uuid4().hex}"]
    kept = AiCallRepository(get_mongodb()[f"test_texts_{uuid.uuid4().hex}"])
    days_ago = [utc_now() - timedelta(days=days) for days in (13, 2, 0)]
    old.insert_many([{"_id": n, "created_at": at, "response": f"text {n}"} for n, at in enumerate(days_ago)])
    old.insert_one({"_id": "untimed", "response": "no time"})
    kept.collection.insert_one({"_id": 0, "response": "kept"})
    assert kept.copy_records_from(old.name) == 4
    assert kept.copy_records_from(old.name) == 4
    assert kept.collection.find_one({"_id": 0})["response"] == "kept"


def test_a_job_re_sent_across_the_rollout_finds_its_answer_in_the_previous_collection() -> None:
    """Review 2026-10-29: a job whose first delivery ran on an old pod kept its answers in tsg_ai_calls; its
    re-send on a new pod asked the AI again. Mutation: read only tsg_ai_call_texts."""
    job = {"record_id": uuid.uuid4().hex, "epoch": 1, "job_task": "tsg_find_threats"}
    previous = {**job, "prompt_hash": "h", "outcome": "ok", "response": '{"n": 1}', "model": "kimi"}
    get_mongodb()["tsg_ai_calls"].insert_one({**previous, "created_at": utc_now()})
    assert AiCallRepository().find_ok_response(job, "h") == ('{"n": 1}', "kimi")


def test_a_busy_add_up_is_one_line_for_the_operator_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Review 2026-10-29: a replay that found the add-up's lock taken ended in a traceback with the reason at
    its foot. Mutation: let Unavailable through."""

    def busy(*_: str) -> str:
        raise Unavailable(AiUsageMessage.ROLLUP_BUSY)

    monkeypatch.setattr(ai_usage_tools, "main", busy)
    assert ai_usage_tools.run(["replay", "-"]) == 1
    assert capsys.readouterr().err.strip() == AiUsageMessage.ROLLUP_BUSY
    monkeypatch.setattr(ai_usage_tools, "main", lambda *_: "done")
    assert ai_usage_tools.run(["roll-up"]) == 0 and capsys.readouterr().out.strip() == "done"

    def too_slow(*_: str) -> str:  # review 2026-10-29: a MongoDB timeout was a traceback too
        raise ExecutionTimeout("MongoDB took too long")

    monkeypatch.setattr(ai_usage_tools, "main", too_slow)
    assert ai_usage_tools.run(["replay", "-"]) == 1
    assert capsys.readouterr().err.strip() == AiUsageMessage.MONGO_TOO_SLOW.format(error="ExecutionTimeout")


def test_the_tool_explains_itself_when_asked_nothing_it_knows() -> None:
    assert "copy-texts" in ai_usage_tools.main("help")
