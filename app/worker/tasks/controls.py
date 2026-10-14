"""Control mapping (Step 13; BUILD_PLAN S34; BLUEPRINT Rules S10-S11; spec v4.0 §7.5.9).

tsg_map_controls maps one run's written scenarios one at a time, each under its own small lease: claim, map,
save, counts, live update. One delivery maps a run at a time: it first takes the run's delivery lease in one
conditional update (ControlDeliveries), so a burst of messages for one run maps it once; the others end at
once. It maps at most Controls.PER_DELIVERY, then hands the lease over and queues the run's next turn behind
whatever waits, so background mapping never holds a worker thread for long (G195). It is not leased on the
run's job and its epoch is not checked: controls belong to scenarios, not to a batch, and reviewers already
see the scenarios while their controls are mapped. tsg_retry_controls (beat) re-queues stalled mappings, one
message per run no delivery serves."""

import time
from typing import Any

import structlog
from celery import Task

from app.ai import background_reranks, get_rerank_model
from app.core.constants import (
    Controls,
    ErrorCode,
    ErrorMessage,
    Lease,
    LogEvent,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import ControlsNotMapped, JobFailed
from app.core.tracing import traced
from app.data_access.run_counts import RunCounts
from app.data_access.scenario_controls import ControlDeliveries, ControlLeases, ControlSweep
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.control_mapper import ControlMapper, controls_record
from app.models.asset_context import FrozenContext
from app.realtime.publisher import publish_session_status
from app.search.service import get_library_search
from app.worker.celery_app import celery_app, send_job
from app.worker.jobs import TEMPORARY_ERRORS, describe_outage, keep_lease_alive

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.MAP_CONTROLS, bind=True)
def map_controls(self: Task, record_id: str, epoch: int) -> None:
    """An outage gives the scenario back and retries this message after the back-off; the scenario fails after
    Controls.MAX_ATTEMPTS, and the sweep tries it again later."""
    structlog.contextvars.bind_contextvars(record_id=record_id)  # jobs.run_job binds it; this task skips it
    try:
        deliveries = ControlDeliveries(get_mongodb())
        # Taken before anything is loaded: a message that finds the run mapped now costs one update. Inside
        # the retry: a store outage here retries the message too (its retry keeps the task id, so it takes the
        # lease back).
        if not deliveries.take(record_id, self.request.id):
            return
        RunControls(record_id, self.request.id, deliveries).map_all()
    except TEMPORARY_ERRORS as exc:
        delays = Lease.RETRY_DELAYS_SECONDS
        raise self.retry(countdown=delays[min(self.request.retries, len(delays) - 1)], exc=exc) from exc


@celery_app.task(name=TaskName.RETRY_CONTROLS)
def retry_controls() -> None:
    """The sweep: stalled mappings queued again, and one message per run they belong to that no delivery
    serves (one maps it now, or its next turn is on its way): read after the requeue, so a run released in
    between still gets its message."""
    db = get_mongodb()
    runs = ControlSweep(db).requeue_stalled()
    for record_id in sorted(set(runs) - ControlDeliveries(db).served(runs)):
        send_job(TaskName.MAP_CONTROLS, record_id, 0)  # the epoch is never checked for controls


class RunControls:
    """One delivery mapping one run's waiting scenarios, holding the run's delivery lease."""

    def __init__(self, record_id: str, task_id: str, deliveries: ControlDeliveries) -> None:
        db = get_mongodb()
        self._record_id, self._task_id, self._deliveries = record_id, task_id, deliveries
        self._leases, self._sweep, self._counts = ControlLeases(db), ControlSweep(db), RunCounts(db)
        self._context = FrozenContext.from_record(SessionRepository(db).find_context(record_id))
        self._snapshot = get_library_search().snapshot()
        self._mapper = ControlMapper(get_rerank_model())

    @traced("worker.map_controls")
    def map_all(self) -> int:
        """How many scenarios this delivery mapped (at most Controls.PER_DELIVERY), the run's counts and
        watchers updated after each. A delivery that used its whole turn hands the run over and queues its
        next turn behind whatever waits (a run's writing above all: live test 2026-10-11)."""
        mapped = 0
        for _ in range(Controls.PER_DELIVERY):
            scenario = self._leases.claim(self._record_id, self._task_id)
            if scenario is None:  # none waits: the run's mapping is done until its next written batch
                self._release()
                return mapped
            started = time.perf_counter()  # high resolution: monotonic ticks every ~16 ms on Windows
            mapped += self._map_one(scenario)
            self._counts.refresh(self._record_id, controls_seconds=time.perf_counter() - started)
            publish_session_status(self._record_id)
            if not self._deliveries.renew(self._record_id, self._task_id):
                return mapped  # the run's lease ran out mid-turn and another delivery took the run over
        self._deliveries.hand_over(self._record_id, self._task_id)
        send_job(TaskName.MAP_CONTROLS, self._record_id, 0)  # the epoch is never checked for controls
        return mapped

    def _release(self) -> None:
        """The run's lease given up; a scenario written meanwhile, whose message found the run still held and
        ended, gets a message of its own (else it would wait for the sweep's 10 minutes)."""
        self._deliveries.release(self._record_id, self._task_id)
        if self._sweep.has_waiting(self._record_id):
            send_job(TaskName.MAP_CONTROLS, self._record_id, 0)

    def _map_one(self, scenario: dict[str, Any]) -> int:
        """1 when its controls were saved. A reason no retry changes now fails that scenario's controls; an
        outage gives it back and is raised; a setting to fix fails it and the job."""
        scenario_id = scenario["_id"]
        try:
            lease = _ScenarioLease(
                (self._deliveries, self._record_id), self._leases, scenario_id, self._task_id
            )
            # Background work: on the laptop's CPU reranker a waiting scenario goes first (G222).
            with keep_lease_alive(lease), background_reranks():
                mapping = self._mapper.map_controls(scenario, self._context, self._snapshot)
        except ControlsNotMapped as exc:
            self._fail(scenario_id, exc.code, exc.message)
            return 0
        except TEMPORARY_ERRORS as exc:
            outage = {"code": ErrorCode.UNAVAILABLE, "message": describe_outage(exc)}
            self._leases.give_back(scenario_id, self._task_id, scenario["controls"]["attempts"], outage)
            raise
        except JobFailed as exc:
            self._fail(scenario_id, exc.code, exc.message)
            raise
        except Exception:  # noqa: BLE001 — one scenario's fault must not cost the run its other scenarios
            log.exception(LogEvent.CONTROLS_MAP_FAILED, scenario_id=scenario_id)
            message = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._record_id)
            self._fail(scenario_id, ErrorCode.INTERNAL_ERROR, message)
            return 0
        saved = self._leases.finish(scenario_id, self._task_id, controls_record(mapping, self._snapshot))
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=saved)
        return int(saved)

    def _fail(self, scenario_id: str, code: str, message: str) -> None:
        log.warning(LogEvent.CONTROLS_NOT_MAPPED, scenario_id=scenario_id, code=code)
        self._leases.fail(scenario_id, self._task_id, {"code": code, "message": message})


class _ScenarioLease:
    """One scenario's control lease as keep_lease_alive renews it, the run's delivery lease with it (a slow
    mapping must not let another delivery take the run over)."""

    def __init__(
        self, delivery: tuple[ControlDeliveries, str], leases: ControlLeases, scenario_id: str, task_id: str
    ) -> None:
        (self._deliveries, self._run_id), self._leases = delivery, leases
        self.record_id, self._task_id = scenario_id, task_id

    def renew(self) -> bool:
        self._deliveries.renew(self._run_id, self._task_id)
        return self._leases.renew(self.record_id, self._task_id)
