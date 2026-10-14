"""What the VS Code tasks run for debugging (docs/DEBUGGING.md): read-only checks of the stores, workers and
queues; one run's job; the log lines of one request, run or job; sending the timer jobs now; and, on the
laptop only, a test run to watch live updates with.

From the project folder: .venv\\Scripts\\python scripts\\debug_tools.py <command> [value]"""

from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from dotenv import dotenv_values  # noqa: E402

DEBUG_ENV = REPO / "debug" / ".env"
SETTINGS = REPO / ".vscode" / "settings.json"
LOG_FILES = ("api.log", "worker-*.log", "beat.log")
RUN_FIELDS = {"entity_id": 1, "asset_id": 1, "status": 1, "step": 1, "job": 1, "updated_at": 1, "test_run": 1}


def debug_value(name: str) -> str:
    """A value from debug/.env (the person's own key and identity), or "" when not set."""
    return (dotenv_values(DEBUG_ENV).get(name) or "") if DEBUG_ENV.exists() else ""


def set_debug_value(name: str, value: str) -> None:
    """Writes NAME=value into debug/.env, replacing the line if there is one."""
    lines = DEBUG_ENV.read_text(encoding="utf-8").splitlines() if DEBUG_ENV.exists() else []
    kept = [line for line in lines if not line.startswith(f"{name}=")]
    DEBUG_ENV.write_text("\n".join([*kept, f"{name}={value}"]) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- read-only checks
def stores(_: str) -> int:
    from app.core.database import get_stored_procedure_client
    from app.data_access.library import LibraryRepository
    from app.services.readiness import check_readiness

    dependencies, workers = check_readiness()
    for name, up in dependencies.items():
        print(f"  {name:6} {'up' if up else 'DOWN'}")
    counts = ", ".join(f"{queue}={count}" for queue, count in (workers or {}).items())
    print(f"  live workers per queue: {counts if workers is not None else 'unknown (check Redis)'}")
    if all(dependencies.values()):
        tables = [table for table, _ in LibraryRepository(get_stored_procedure_client()).read_library_stamp()]
        print(f"  library tables SQL Server reports: {len(tables)} ({', '.join(tables)})")
    return 0 if all(dependencies.values()) and workers and all(workers.values()) else 1


def workers(_: str) -> int:
    from app.worker import celery_app

    inspect = celery_app.control.inspect(timeout=2)
    alive = inspect.ping() or {}
    if not alive:
        print("  No worker answered within 2 s. Start one ('TSG: start') or read the window 'TSG worker'.")
        print("  A worker stopped at a breakpoint ('Debug worker') answers only after you continue (F5).")
        return 1
    print(f"  answering: {', '.join(sorted(alive))}")
    for label, answer in (
        ("running now", inspect.active() or {}),
        ("taken, not started yet", inspect.reserved() or {}),
        ("retries waiting for their delay", inspect.scheduled() or {}),
    ):
        jobs = [(worker, job.get("request", job)) for worker, items in answer.items() for job in items]
        print(f"  {label}: {len(jobs)}")
        for worker, job in jobs:
            print(f"    {worker}  {job.get('name')}  task_id={job.get('id')}  args={job.get('args')}")
    return 0


def queues(_: str) -> int:
    from app.worker.celery_app import ROUTED_QUEUES, count_waiting_messages

    for queue in ROUTED_QUEUES:
        print(f"  {queue:16} {count_waiting_messages(queue)} waiting")
    return 0


def run_show(run_id: str) -> int:
    from app.core.constants import Collection
    from app.core.database import get_mongodb

    run_id = run_id or debug_value("TSG_RUN_ID")
    record = get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id}, RUN_FIELDS)
    if record is None:
        print(f"  No run with id '{run_id}'.")
        return 1
    print(json.dumps(record, indent=2, default=str))
    return 0


def find(text: str) -> int:
    """Every log line containing text (a request id, run id or task id), oldest first, shortened to its key
    fields."""
    from app.core.config import get_settings

    folder = REPO / (get_settings().log_dir or "logs")
    found = 0
    for path in sorted(p for pattern in LOG_FILES for p in folder.glob(pattern)):
        with path.open(encoding="utf-8", errors="replace") as lines:  # line by line: the files never rotate
            for line in lines:
                if text and text in line:
                    found += 1
                    print(f"{path.name}: {_short(line.rstrip())}")
    print(f"  {found} line(s) with '{text}' in {folder}")
    return 0 if found else 1


def _short(line: str) -> str:
    try:
        fields = json.loads(line)
    except ValueError:
        return line  # beat's plain-text lines
    keys = ("timestamp", "level", "event", "status", "route", "record_id", "task_id", "error", "reason")
    return "  ".join(f"{key}={fields[key]}" for key in keys if fields.get(key) not in (None, ""))


# ---------------------------------------------------------------- actions
def send(task: str) -> int:
    """Sends a timer job now (the same job beat sends on its schedule)."""
    from app.core.constants import TaskName
    from app.worker import celery_app

    name = {"reaper": TaskName.REAP, "indexes": TaskName.BUILD_LIBRARY_INDEXES}[task]
    result = celery_app.send_task(name)
    print(f"  sent {name}: task_id={result.id}. Watch the window 'TSG worker', or 'TSG: find in the logs'.")
    return 0


def stream(environment: str) -> int:
    """The live updates of the run in debug/.env (TSG_RUN_ID), as a caller receives them. Ctrl+C ends it."""
    import httpx

    from app.core.constants import Header

    variables = json.loads(SETTINGS.read_text(encoding="utf-8"))["rest-client.environmentVariables"]
    base_url = {**variables["$shared"], **variables.get(environment, {})}["baseUrl"]
    headers: dict[str, str] = {
        Header.API_KEY: debug_value("TSG_API_KEY"),
        Header.USER_ID: debug_value("TSG_USER_ID"),
        Header.ENTITY_ID: debug_value("TSG_ENTITY_ID"),
        Header.TENANT_ID: debug_value("TSG_TENANT_ID"),
    }
    url = f"{base_url}/v1/sessions/{debug_value('TSG_RUN_ID')}/events"
    print(f"  {url}  (Ctrl+C to stop)")
    try:
        with httpx.stream("GET", url, headers=headers, timeout=httpx.Timeout(10, read=None)) as response:
            if response.status_code != 200:
                print(f"  Status {response.status_code}, request id {response.headers.get('X-Request-Id')}")
                print(f"  {response.read().decode()}")
                return 1
            for line in response.iter_lines():
                print(line, flush=True)
    except KeyboardInterrupt:
        pass
    except httpx.HTTPError as exc:  # the API is not running, or stopped while streaming
        print(f"  The stream ended: {exc}. Is the API running ('TSG: status')? Run this task again.")
        return 1
    return 0


def _laptop_only() -> None:
    from app.core.config import get_settings
    from app.core.constants import Env

    if get_settings().env is not Env.DEV:
        raise SystemExit("  Test runs are for the laptop only (CII_ENV=dev in .env).")


def run_make(_: str) -> int:
    from app.core.constants import Collection, Status, Step
    from app.core.database import get_mongodb

    _laptop_only()
    run_id, entity_id = uuid.uuid4().hex, int(debug_value("TSG_ENTITY_ID") or 86)
    get_mongodb()[Collection.SESSIONS].insert_one(
        {
            "_id": run_id,
            "entity_id": entity_id,
            "asset_id": 103,
            "status": Status.RUNNING,
            "step": Step.THREATS,
            "test_run": True,  # made by this tool: the only kind 'run-delete' may remove
            "updated_at": datetime.now(UTC),
        }
    )
    set_debug_value("TSG_RUN_ID", run_id)
    print(f"  test run {run_id} made for entity {entity_id}; saved as TSG_RUN_ID")
    return 0


def run_change(status: str) -> int:
    from app.core.constants import Collection
    from app.core.database import get_mongodb
    from app.realtime.publisher import publish_session_status

    _laptop_only()
    run_id = debug_value("TSG_RUN_ID")
    changed = get_mongodb()[Collection.SESSIONS].update_one(
        {"_id": run_id, "test_run": True}, {"$set": {"status": status, "updated_at": datetime.now(UTC)}}
    )
    if not changed.matched_count:
        print(f"  No test run '{run_id}': make one first ('TSG: make a test run').")
        return 1
    publish_session_status(run_id)  # what a worker does after each change
    print(f"  test run {run_id} is now '{status}' and the change was announced")
    return 0


def run_delete(_: str) -> int:
    from app.core.constants import Collection
    from app.core.database import get_mongodb

    _laptop_only()
    run_id = debug_value("TSG_RUN_ID")
    deleted = get_mongodb()[Collection.SESSIONS].delete_one({"_id": run_id, "test_run": True}).deleted_count
    set_debug_value("TSG_RUN_ID", "")
    print(f"  {'deleted' if deleted else 'no test run to delete with id'} '{run_id}'")
    return 0


COMMANDS: dict[str, Callable[[str], int]] = {
    "stores": stores,
    "workers": workers,
    "queues": queues,
    "run-show": run_show,
    "find": find,
    "send": send,
    "stream": stream,
    "run-make": run_make,
    "run-change": run_change,
    "run-delete": run_delete,
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        raise SystemExit(f"usage: debug_tools.py {{{'|'.join(COMMANDS)}}} [value]")
    sys.exit(COMMANDS[sys.argv[1]](sys.argv[2] if len(sys.argv) > 2 else ""))
