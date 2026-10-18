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
    Status,
    TaskName,
)
from app.core.exceptions import TEMPORARY_ERRORS, ControlsNotMapped, JobFailed, LeaseLost
from app.data_access.scenario.repository import controls_deliveries, scenario_controls, scenarios
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
        # Taken before anything is loaded, so a message that finds the run being mapped costs one update.
        context = controls_deliveries.claim_controls_delivery(record_id, self.request.id)
        if context is None:
            return
        RunControls(record_id, self.request.id, context).map_all()
    except TEMPORARY_ERRORS as exc:
        delays = Lease.RETRY_DELAYS_SECONDS
        raise self.retry(countdown=delays[min(self.request.retries, len(delays) - 1)], exc=exc) from exc


@celery_app.task(name=TaskName.RETRY_CONTROLS)
def retry_controls() -> None:
    """Beat task: requeue stalled mappings, then send one message per run they belong to that no delivery
    serves (read after the requeue, so a run released in between still gets its message)."""
    session_ids = scenario_controls.requeue_stalled_controls()
    live = controls_deliveries.list_scenario_sessions_with_live_delivery(session_ids)
    for record_id in sorted(set(session_ids) - live):
        send_job(TaskName.MAP_CONTROLS, record_id, 0)  # the epoch is never checked for controls


class RunControls:
    """One delivery mapping one run's waiting scenarios, holding the run's delivery lease."""

    def __init__(self, record_id: str, task_id: str, context: dict[str, Any]) -> None:
        """`context`: the run's frozen context, as its delivery claim returned it."""
        self._record_id, self._task_id = record_id, task_id
        self._context = FrozenContext.from_record(context)
        self._snapshot = get_library_search().snapshot()
        self._mapper = ControlMapper(get_rerank_model())

    def map_all(self) -> int:
        """Map up to Controls.PER_DELIVERY scenarios, updating the run's counts and watchers after each; a
        delivery that used its whole turn hands the run over and queues its next turn behind other work."""
        mapped = 0
        for _ in range(Controls.PER_DELIVERY):
            scenario = scenario_controls.claim_scenario_controls(self._record_id, self._task_id)
            if scenario is None:  # none waits: the run's mapping is done until its next written batch
                self._release()
                return mapped
            started = time.perf_counter()  # high resolution: monotonic ticks every ~16 ms on Windows
            mapped += self._map_one(scenario)
            scenarios.update_scenario_session_counts(
                self._record_id, controls_seconds=time.perf_counter() - started
            )
            publish_session_status(self._record_id)
            if not controls_deliveries.update_controls_delivery(self._record_id, self._task_id):
                return mapped  # the run's lease ran out mid-turn and another delivery took the run over
        controls_deliveries.update_controls_delivery(self._record_id, self._task_id, hand_over=True)
        send_job(TaskName.MAP_CONTROLS, self._record_id, 0)  # the epoch is never checked for controls
        return mapped

    def _release(self) -> None:
        """Give up the run's lease; a scenario written meanwhile, whose message found the run held, gets a
        message of its own instead of waiting for the sweep."""
        controls_deliveries.release_controls_delivery(self._record_id, self._task_id)
        if scenario_controls.count(session_id=self._record_id, controls_waiting=True):
            send_job(TaskName.MAP_CONTROLS, self._record_id, 0)

    def _map_one(self, scenario: dict[str, Any]) -> int:
        """Map and save one scenario's controls: 1 when saved. A reason no retry changes fails its controls;
        an outage gives it back and is raised; a job-wide failure fails it and is raised; a lost lease skips
        it."""
        scenario_id, attempts = scenario["_id"], scenario["controls"]["attempts"]
        try:
            lease = _ScenarioLease(self._record_id, (scenario_id, attempts), self._task_id)
            # Background work: on a local CPU reranker any waiting foreground rerank goes first.
            with keep_lease_alive(lease), background_reranks():
                mapping = self._mapper.map_controls(scenario, self._context, self._snapshot)
        except ControlsNotMapped as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            return 0
        except TEMPORARY_ERRORS as exc:
            outage = {"code": ErrorCode.UNAVAILABLE, "message": describe_outage(exc)}
            scenario_controls.update_scenario_controls(
                scenario_id, self._task_id, attempts, Status.QUEUED, error=outage
            )
            raise
        except JobFailed as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            raise
        except LeaseLost:  # its run was cancelled, or another delivery took the scenario over
            return 0
        except Exception:  # one scenario's fault must not cost the run its other scenarios
            log.exception(LogEvent.CONTROLS_MAP_FAILED, scenario_id=scenario_id)
            message = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._record_id)
            self._fail(scenario_id, attempts, ErrorCode.INTERNAL_ERROR, message)
            return 0
        saved = scenario_controls.update_scenario_controls(
            scenario_id,
            self._task_id,
            attempts,
            Status.DONE,
            mapping=controls_record(mapping, self._snapshot),
        )
        log.info(LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping.items), saved=saved)
        return int(saved)

    def _fail(self, scenario_id: str, attempts: int, code: str, message: str) -> None:
        """Log and save why one scenario's controls were not mapped."""
        log.warning(LogEvent.CONTROLS_NOT_MAPPED, scenario_id=scenario_id, code=code)
        error = {"code": code, "message": message}
        scenario_controls.update_scenario_controls(
            scenario_id, self._task_id, attempts, Status.FAILED, error=error
        )


class _ScenarioLease:
    """One scenario's control lease as keep_lease_alive renews it, renewing the run's delivery lease too (a
    slow mapping must not let another delivery take the run over)."""

    def __init__(self, session_id: str, claim: tuple[str, int], task_id: str) -> None:
        """`claim`: the scenario id and the attempts its claim counted."""
        self._session_id, (self.record_id, self._attempts), self._task_id = session_id, claim, task_id

    def renew(self) -> bool:
        """Renew the run's delivery lease and this scenario's lease; True while the scenario's holds."""
        controls_deliveries.update_controls_delivery(self._session_id, self._task_id)
        return scenario_controls.update_scenario_controls(
            self.record_id, self._task_id, self._attempts, Status.RUNNING
        )
