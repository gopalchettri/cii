"""Readiness: every store answers and every routed queue has a live worker, and the MongoDB topology. Read by
/ready and /metrics (app/api/routers/health.py) and logged at start-up."""

import asyncio
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any

import pymongo
import structlog

from app.core import metrics
from app.core.clock import epoch_seconds
from app.core.constants import ROUTED_QUEUES, Dependency, LogEvent, Timeouts, Worker
from app.core.database import get_mongodb, get_redis_client, get_stored_procedure_client

log = structlog.get_logger(__name__)


def _ping_mongo() -> object:
    # Bounded here too: a ping on an open but dead connection would otherwise wait the 30 s socket timeout.
    with pymongo.timeout(Timeouts.READY_CHECK_SECONDS):
        return get_mongodb().command("ping")


_DEPENDENCY_CHECKS: dict[Dependency, Callable[[], object]] = {
    Dependency.MONGO: _ping_mongo,
    # A probe runs every few seconds, so it only proves SQL Server answers; it never runs a procedure.
    Dependency.SQL: lambda: get_stored_procedure_client().check_connection(),
    Dependency.REDIS: lambda: get_redis_client().ping(),
}


_WORKERS_CHECK = "workers"


_TOPOLOGY_CHECK = "mongodb_topology"


@dataclass
class _Run:
    """One run of one check. `reported` makes its outcome logged once, however many calls read it."""

    future: Future
    started: float
    reported: bool = False


# /ready and /metrics are public, so callers must not be able to multiply the work: each check runs at most
# once per Timeouts.READY_CHECK_REUSE_SECONDS per process, and a check that hangs (a network black hole) is
# never started again while it hangs. Every call in between reads the same run.
_CHECKS = ThreadPoolExecutor(max_workers=len(_DEPENDENCY_CHECKS) + 2, thread_name_prefix="ready")


_runs: dict[str, _Run] = {}


_runs_lock = threading.Lock()


def _current_run(name: str, check: Callable[..., object], *args: object) -> _Run:
    now = time.monotonic()
    with _runs_lock:
        run = _runs.get(name)
        if run is None or (run.future.done() and now - run.started >= Timeouts.READY_CHECK_REUSE_SECONDS):
            run = _runs[name] = _Run(_CHECKS.submit(check, *args), now)
        return run


Readiness = tuple[dict[Dependency, bool], dict[str, int] | None]


def count_online_workers(queues: Iterable[str]) -> dict[str, int]:
    """Worker pods per queue whose last heartbeat is recent enough; one Redis round trip."""
    names = list(queues)
    since = epoch_seconds() - Worker.ONLINE_WITHIN_SECONDS
    with get_redis_client().pipeline(transaction=False) as pipe:
        for queue in names:
            pipe.zcount(Worker.HEARTBEAT_KEY.format(queue=queue), since, "+inf")
        counts = pipe.execute()
    return dict(zip(names, counts, strict=True))


def describe_mongodb_topology() -> dict[str, Any]:
    """The MongoDB server this process writes to: its replica set's name (or standalone), its version and its
    default write concern (None when the server does not say, e.g. the user lacks the privilege)."""
    with pymongo.timeout(Timeouts.READY_CHECK_SECONDS):
        admin = get_mongodb().client.admin
        replica_set = admin.command("hello").get("setName") or "standalone"
        version = admin.command("buildInfo")["version"]
        try:
            write_concern = admin.command("getDefaultRWConcern").get("defaultWriteConcern")
        except pymongo.errors.OperationFailure:
            write_concern = None
    return {"replica_set": replica_set, "version": version, "default_write_concern": write_concern}


def log_mongodb_topology() -> None:
    """One start-up line naming the MongoDB topology (API and each worker) and the write concern every write
    uses; never fails start-up."""
    try:
        write_concern = get_mongodb().write_concern.document
        log.info(LogEvent.MONGODB_TOPOLOGY, **describe_mongodb_topology(), write_concern=write_concern)
    except Exception:  # noqa: BLE001 — a report only: a store that does not answer fails elsewhere
        log.warning(LogEvent.MONGODB_TOPOLOGY, replica_set=None, exc_info=True)


def check_readiness() -> Readiness:
    """Each store up or down, and live workers per queue; sets tsg_dependency_up and tsg_workers_online.
    A check still running Timeouts.READY_CHECK_SECONDS after it started counts as down."""
    runs, workers_run = _start_runs()
    pending, left = _still_within_bound([*runs.values(), workers_run])
    if pending:
        wait([run.future for run in pending], timeout=left)
    return _results(runs, workers_run)


async def check_readiness_without_a_thread() -> Readiness:
    """check_readiness for the API's public /ready and /metrics: it waits on the checks without holding one
    of the threads every other route needs, so many calls during a slow outage cannot stall the API."""
    runs, workers_run = _start_runs()
    pending, left = _still_within_bound([*runs.values(), workers_run])
    if pending:
        waiting = [asyncio.wrap_future(run.future) for run in pending]
        for future in waiting:
            future.add_done_callback(_mark_seen)
        await asyncio.wait(waiting, timeout=left)
    return _results(runs, workers_run)


def _start_runs() -> tuple[dict[Dependency, _Run], _Run]:
    runs = {name: _current_run(name, check) for name, check in _DEPENDENCY_CHECKS.items()}
    _current_run(_TOPOLOGY_CHECK, describe_mongodb_topology)  # started with the others, never waited for
    return runs, _current_run(_WORKERS_CHECK, count_online_workers, ROUTED_QUEUES)


def read_mongodb_topology() -> dict[str, object] | None:
    """The MongoDB topology for /ready, never waited for: None until its run answered (or if it failed)."""
    run = _current_run(_TOPOLOGY_CHECK, describe_mongodb_topology)
    if not run.future.done() or run.future.exception() is not None:
        return None
    return run.future.result()


def _results(runs: dict[Dependency, _Run], workers_run: _Run) -> Readiness:
    return {name: _report_dependency(name, run) for name, run in runs.items()}, _report_workers(workers_run)


def _mark_seen(future: asyncio.Future[object]) -> None:
    """A failed check's error also reaches its asyncio copy, which nobody reads (_results reads the
    original): unread, asyncio logs "Future exception was never retrieved" as plain text on every probe
    and scrape for as long as the outage lasts."""
    if not future.cancelled():
        future.exception()


def _still_within_bound(runs: list[_Run]) -> tuple[list[_Run], float]:
    """The runs worth waiting for, and what is left of their bound: a run that started earlier was already
    waited for by an earlier call, so a hung store costs the first caller 5 s and every later caller nothing.
    Only runs still inside their bound: a wait ends when ALL its futures are done, and a hung run (already
    past its bound, already counted down) would make every later call wait the full bound again."""
    now = time.monotonic()
    pending = [
        run for run in runs if not run.future.done() and now - run.started < Timeouts.READY_CHECK_SECONDS
    ]
    left = max((Timeouts.READY_CHECK_SECONDS - (now - run.started) for run in pending), default=0)
    return (pending, left) if left > 0 else ([], 0)


def _report_dependency(name: Dependency, run: _Run) -> bool:
    """Up or down; sets tsg_dependency_up and logs a failure once per run."""
    try:
        run.future.result(timeout=0)  # already waited for; still running = too slow = down
        up = True
    except Exception:  # noqa: BLE001 — a probe reports, it never raises
        if _first_report(run):
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=name, exc_info=True)
        up = False
    metrics.record_dependency_status(name, up)
    return up


def _report_workers(run: _Run) -> dict[str, int] | None:
    """Live workers per queue, set in tsg_workers_online; None when the count could not be read (logged
    once per run: Redis may answer PING and still fail this read, e.g. on a key of the wrong type)."""
    try:
        online: dict[str, int] = run.future.result(timeout=0)
    except Exception:  # noqa: BLE001 — a probe reports, it never raises
        # Unknown, not "still N": a stale count would show workers that nobody can see any more.
        metrics.WORKERS_ONLINE.clear()
        if _first_report(run):
            log.warning(LogEvent.WORKERS_UNKNOWN, exc_info=True)
        return None
    report = _first_report(run)
    for queue, count in online.items():
        metrics.record_workers_online(queue, count)
        if not count and report:
            log.warning(LogEvent.WORKER_NONE_ONLINE, queue=queue)
    return online


def _first_report(run: _Run) -> bool:
    """True for the first reader of a run's outcome only, so one outage logs one line, not one per call."""
    with _runs_lock:
        first, run.reported = not run.reported, True
        return first
