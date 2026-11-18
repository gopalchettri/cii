"""Readiness: every store answers and every routed queue has a live worker, and the MongoDB topology."""

import asyncio
import threading
import time
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Any, cast

import pymongo
import structlog

from app.core import metrics
from app.core.clock import epoch_seconds
from app.core.constants import ROUTED_QUEUES, Dependency, LogEvent, Timeouts, Worker
from app.core.database import get_mongodb, get_redis_client, get_stored_procedure_client

log = structlog.get_logger(__name__)


def _ping_mongo() -> object:
    with pymongo.timeout(Timeouts.READY_CHECK_SECONDS):  # an open but dead socket would wait 30 s
        return get_mongodb().command("ping")


_DEPENDENCY_CHECKS: dict[Dependency, Callable[[], object]] = {
    Dependency.MONGO: _ping_mongo,
    Dependency.SQL: lambda: get_stored_procedure_client().check_connection(),  # never runs a procedure
    Dependency.REDIS: lambda: get_redis_client().ping(),
}
_WORKERS_CHECK, _TOPOLOGY_CHECK = "workers", "mongodb_topology"
# ponytail: public probes cannot multiply work: a check runs at most once per READY_CHECK_REUSE_SECONDS per
# process, and one that hangs is never started again while it hangs.
_CHECKS = ThreadPoolExecutor(max_workers=len(_DEPENDENCY_CHECKS) + 2, thread_name_prefix="ready")
_runs: dict[str, list[Any]] = {}  # name -> [future, started, reported]
_runs_lock = threading.Lock()

Readiness = tuple[dict[Dependency, bool], dict[str, int] | None]


def _current_run(name: str, check: Callable[..., object], *args: object) -> list[Any]:
    now = time.monotonic()
    with _runs_lock:
        run = _runs.get(name)
        if run is None or (run[0].done() and now - run[1] >= Timeouts.READY_CHECK_REUSE_SECONDS):
            run = _runs[name] = [_CHECKS.submit(check, *args), now, False]
        return run


def count_online_workers(queues: Iterable[str]) -> dict[str, int]:
    """Worker pods per queue whose last heartbeat is recent enough; one Redis round trip."""
    names = list(queues)
    since = epoch_seconds() - Worker.ONLINE_WITHIN_SECONDS
    with get_redis_client().pipeline(transaction=False) as pipe:
        for queue in names:
            pipe.zcount(Worker.HEARTBEAT_KEY.format(queue=queue), since, "+inf")
        return dict(zip(names, pipe.execute(), strict=True))


def describe_mongodb_topology() -> dict[str, Any]:
    """Replica set (or standalone), version and default write concern of the MongoDB this process uses."""
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
    """One start-up line naming the MongoDB topology and the write concern every write uses."""
    try:
        write_concern = get_mongodb().write_concern.document
        log.info(LogEvent.MONGODB_TOPOLOGY, **describe_mongodb_topology(), write_concern=write_concern)
    except Exception:  # noqa: BLE001 — a report only: a store that does not answer fails elsewhere
        log.warning(LogEvent.MONGODB_TOPOLOGY, replica_set=None, exc_info=True)


def log_redis_eviction_policy() -> None:
    """One start-up line naming Redis' maxmemory-policy: an error unless noeviction (keys would be dropped)."""
    try:
        policy = cast(dict[str, Any], get_redis_client().info("memory")).get("maxmemory_policy")
    except Exception:  # noqa: BLE001 — a report only: a Redis that does not answer fails elsewhere
        log.warning(LogEvent.REDIS_EVICTION_POLICY, maxmemory_policy=None, exc_info=True)
        return
    (log.info if policy == "noeviction" else log.error)(LogEvent.REDIS_EVICTION_POLICY, maxmemory_policy=policy)


def _start_runs() -> tuple[dict[Dependency, list[Any]], list[Any]]:
    runs = {name: _current_run(name, check) for name, check in _DEPENDENCY_CHECKS.items()}
    _current_run(_TOPOLOGY_CHECK, describe_mongodb_topology)  # started with the others, never waited for
    return runs, _current_run(_WORKERS_CHECK, count_online_workers, ROUTED_QUEUES)


def _pending(runs: Iterable[list[Any]]) -> tuple[list[Future], float]:
    now = time.monotonic()
    live = [run for run in runs if not run[0].done() and now - run[1] < Timeouts.READY_CHECK_SECONDS]
    return [run[0] for run in live], max((Timeouts.READY_CHECK_SECONDS - (now - run[1]) for run in live), default=0)


def check_readiness() -> Readiness:
    """Each store up or down, and live workers per queue; sets tsg_dependency_up and tsg_workers_online."""
    runs, workers_run = _start_runs()
    wait(*_pending([*runs.values(), workers_run]))
    return {name: _report_dependency(name, run) for name, run in runs.items()}, _report_workers(workers_run)


def check_stores(names: Iterable[Dependency]) -> dict[Dependency, bool]:
    """Each named store up or down, set in tsg_dependency_up: a worker's own view, which no /metrics shows."""
    runs = {name: _current_run(name, _DEPENDENCY_CHECKS[name]) for name in names}
    wait(*_pending(runs.values()))
    return {name: _report_dependency(name, run) for name, run in runs.items()}


async def check_readiness_without_a_thread() -> Readiness:
    """check_readiness for the public /ready and /metrics, waited on without holding a request thread."""
    runs, workers_run = _start_runs()
    futures, left = _pending([*runs.values(), workers_run])
    if futures:
        waiting = [asyncio.wrap_future(future) for future in futures]
        for copy in waiting:  # read its error, or asyncio logs "Future exception was never retrieved"
            copy.add_done_callback(lambda done: done.cancelled() or done.exception())
        await asyncio.wait(waiting, timeout=left)
    return {name: _report_dependency(name, run) for name, run in runs.items()}, _report_workers(workers_run)


def read_mongodb_topology() -> dict[str, object] | None:
    """The MongoDB topology for /ready, never waited for: None until its run answered (or if it failed)."""
    future = _current_run(_TOPOLOGY_CHECK, describe_mongodb_topology)[0]
    return future.result() if future.done() and future.exception() is None else None


def _report_dependency(name: Dependency, run: list[Any]) -> bool:
    try:
        run[0].result(timeout=0)  # already waited for; still running = too slow = down
        up = True
    except Exception:  # noqa: BLE001 — a probe reports, it never raises
        if _first_report(run):
            log.warning(LogEvent.DEPENDENCY_UNAVAILABLE, dependency=name, exc_info=True)
        up = False
    metrics.DEPENDENCY_UP.labels(name).set(1 if up else 0)
    return up


def _report_workers(run: list[Any]) -> dict[str, int] | None:
    try:
        online: dict[str, int] = run[0].result(timeout=0)
    except Exception:  # noqa: BLE001 — unknown, not "still N": a stale count would show workers nobody sees
        metrics.WORKERS_ONLINE.clear()
        if _first_report(run):
            log.warning(LogEvent.WORKERS_UNKNOWN, exc_info=True)
        return None
    report = _first_report(run)
    for queue, count in online.items():
        metrics.WORKERS_ONLINE.labels(queue).set(count)
        if not count and report:
            log.warning(LogEvent.WORKER_NONE_ONLINE, queue=queue)
    return online


def _first_report(run: list[Any]) -> bool:
    with _runs_lock:
        first, run[2] = not run[2], True
        return first
