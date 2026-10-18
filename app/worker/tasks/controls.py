"""The control mapping jobs: one delivery at a time maps a run's written scenarios, each under its own
lease, and a beat sweep requeues stalled ones. Controls belong to scenarios: the epoch is not checked."""

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
from app.core.exceptions import TEMPORARY_ERRORS, ControlsNotMapped, JobFailed
from app.data_access.scenario.runs import SessionRepository
from app.data_access.scenario.scenarios import ControlDeliveries, ControlLeases, ControlSweep, RunCounts
from app.domain.scenario.controls import ControlMapper, controls_record
from app.models.asset_context import FrozenContext
from app.realtime.publisher import publish_session_status
from app.search.service import get_library_search
from app.worker.celery_app import celery_app, send_job
from app.worker.jobs import describe_outage, keep_lease_alive

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.MAP_CONTROLS, bind=True)
def map_controls(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: take the run's delivery lease and map its waiting scenarios; an outage retries the
    message after the back-off."""
    structlog.contextvars.bind_contextvars(record_id=record_id)  # jobs.run_job binds it; this task skips it
    try:
        deliveries = ControlDeliveries(get_mongodb())
        # Taken before anything is loaded, so a message that finds the run being mapped costs one update.
        if not deliveries.take(record_id, self.request.id):
            return
        RunControls(record_id, self.request.id, deliveries).map_all()
    except TEMPORARY_ERRORS as exc:
        delays = Lease.RETRY_DELAYS_SECONDS
        raise self.retry(countdown=delays[min(self.request.retries, len(delays) - 1)], exc=exc) from exc


@celery_app.task(name=TaskName.RETRY_CONTROLS)
def retry_controls() -> None:
    """Beat task: requeue stalled mappings, then send one message per run they belong to that no delivery
    serves (read after the requeue, so a run released in between still gets its message)."""
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

    def map_all(self) -> int:
        """Map up to Controls.PER_DELIVERY scenarios, updating the run's counts and watchers after each; a
        delivery that used its whole turn hands the run over and queues its next turn behind other work."""
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
        """Give up the run's lease; a scenario written meanwhile, whose message found the run held, gets a
        message of its own instead of waiting for the sweep."""
        self._deliveries.release(self._record_id, self._task_id)
        if self._sweep.has_waiting(self._record_id):
            send_job(TaskName.MAP_CONTROLS, self._record_id, 0)

    def _map_one(self, scenario: dict[str, Any]) -> int:
        """Map and save one scenario's controls: 1 when saved. A reason no retry changes fails its controls;
        an outage gives it back and is raised; a job-wide failure fails it and is raised."""
        scenario_id, attempts = scenario["_id"], scenario["controls"]["attempts"]
        try:
            lease = _ScenarioLease(
                (self._deliveries, self._record_id), self._leases, (scenario_id, attempts), self._task_id
            )
            # Background work: on a local CPU reranker any waiting foreground rerank goes first.
            with keep_lease_alive(lease), background_reranks():
                mapping = self._mapper.map_controls(scenario, self._context, self._snapshot)
        except ControlsNotMapped as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            return 0
        except TEMPORARY_ERRORS as exc:
            outage = {"code": ErrorCode.UNAVAILABLE, "message": describe_outage(exc)}
            self._leases.give_back(scenario_id, self._task_id, attempts, outage)
            raise
        except JobFailed as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            raise
        except Exception:  # one scenario's fault must not cost the run its other scenarios
            log.exception(LogEvent.CONTROLS_MAP_FAILED, scenario_id=scenario_id)
            message = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._record_id)
            self._fail(scenario_id, attempts, ErrorCode.INTERNAL_ERROR, message)
            return 0
        saved = self._leases.finish(
            scenario_id, self._task_id, attempts, controls_record(mapping, self._snapshot)
        )
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=saved)
        return int(saved)

    def _fail(self, scenario_id: str, attempts: int, code: str, message: str) -> None:
        """Log and save why one scenario's controls were not mapped."""
        log.warning(LogEvent.CONTROLS_NOT_MAPPED, scenario_id=scenario_id, code=code)
        self._leases.fail(scenario_id, self._task_id, attempts, {"code": code, "message": message})


class _ScenarioLease:
    """One scenario's control lease as keep_lease_alive renews it, renewing the run's delivery lease too (a
    slow mapping must not let another delivery take the run over)."""

    def __init__(
        self,
        delivery: tuple[ControlDeliveries, str],
        leases: ControlLeases,
        claim: tuple[str, int],
        task_id: str,
    ) -> None:
        """`claim`: the scenario id and the attempts its claim counted."""
        (self._deliveries, self._run_id), self._leases = delivery, leases
        (self.record_id, self._attempts), self._task_id = claim, task_id

    def renew(self) -> bool:
        """Renew the run's delivery lease and this scenario's lease; True while the scenario's holds."""
        self._deliveries.renew(self._run_id, self._task_id)
        return self._leases.renew(self.record_id, self._task_id, self._attempts)
