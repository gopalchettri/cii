"""The VS Code debugging tasks (scripts/debug_tools.py, docs/DEBUGGING.md): the test-run cycle, its safety
rule, the log search, and a stream that ends with a plain message instead of a stack trace."""

import importlib
import json
import socket
import sys
from pathlib import Path

import pytest

from app.core.constants import Collection
from app.core.database import get_mongodb

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):  # type: ignore[no-untyped-def]
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        module = importlib.import_module("debug_tools")
    finally:
        sys.path.remove(str(REPO / "scripts"))
    monkeypatch.setattr(module, "DEBUG_ENV", tmp_path / ".env")  # never the person's own debug/.env
    (tmp_path / ".env").write_text("TSG_ENTITY_ID=86\nTSG_RUN_ID=\n", encoding="utf-8")
    return module


def test_a_test_run_is_made_changed_and_deleted_and_only_a_test_run_is_deleted(tools) -> None:  # type: ignore[no-untyped-def]
    assert tools.run_make("") == 0
    run_id = tools.debug_value("TSG_RUN_ID")
    sessions = get_mongodb()[Collection.SESSIONS]
    assert sessions.find_one({"_id": run_id})["test_run"] is True
    assert tools.run_change("done") == 0
    assert sessions.find_one({"_id": run_id})["status"] == "done"
    assert tools.run_show(run_id) == 0
    assert tools.run_delete("") == 0
    assert sessions.find_one({"_id": run_id}) is None and tools.debug_value("TSG_RUN_ID") == ""
    # A real run (no test_run mark) is never changed or deleted by the tool, even if its id is in debug/.env.
    sessions.insert_one({"_id": "real-run", "entity_id": 86, "status": "running"})
    tools.set_debug_value("TSG_RUN_ID", "real-run")
    assert tools.run_change("failed") == 1
    tools.run_delete("")
    assert sessions.find_one({"_id": "real-run"})["status"] == "running"
    sessions.delete_one({"_id": "real-run"})


def test_find_shows_the_key_fields_of_each_matching_line(tools, capsys: pytest.CaptureFixture[str]) -> None:  # type: ignore[no-untyped-def]
    from app.core.config import get_settings

    line = {
        "event": "http.request",
        "status": 500,
        "route": "/x",
        "request_id": "find-me-123",
        "level": "info",
    }
    (Path(get_settings().log_dir) / "api.log").write_text(json.dumps(line) + "\n", encoding="utf-8")
    assert tools.find("find-me-123") == 0
    assert "event=http.request  status=500  route=/x" in capsys.readouterr().out


def test_find_reads_the_rolled_over_copies_oldest_first(tools, capsys: pytest.CaptureFixture[str]) -> None:  # type: ignore[no-untyped-def]
    """Before: find read only the current <role>.log, so after a 50 MB rollover a request's older lines were
    never found."""
    from app.core.config import get_settings

    folder = Path(get_settings().log_dir)
    names = ["worker-find.log.2", "worker-find.log.1", "worker-find.log"]  # oldest to newest
    for name in names:
        (folder / name).write_text(json.dumps({"event": "job.started", "request_id": "rolled-7"}) + "\n")
    try:
        assert tools.find("rolled-7") == 0
        shown = [line.split(": ", 1)[0] for line in capsys.readouterr().out.splitlines()]
        assert [name for name in shown if name.startswith("worker-find")] == names
    finally:
        for name in names:
            (folder / name).unlink()


def test_a_stream_to_an_api_that_is_not_running_ends_with_a_plain_message(
    tools, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:  # type: ignore[no-untyped-def]
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]  # free: nothing listens there
    settings = tmp_path / "settings.json"
    variables = {"$shared": {"baseUrl": f"http://127.0.0.1:{port}"}}
    settings.write_text(json.dumps({"rest-client.environmentVariables": variables}), encoding="utf-8")
    tools.SETTINGS = settings
    assert tools.stream("laptop") == 1
    assert "The stream ended" in capsys.readouterr().out
