"""The control mapping jobs: one delivery at a time maps a run's written scenarios, each under its own
lease, and a beat sweep requeues stalled ones. Controls belong to scenarios: the epoch is not checked."""

import contextlib
import time
from datetime import datetime, timedelta
from typing import Any

import structlog

from app.ai import RerankModel, background_reranks
from app.ai.common import outage_reason
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    Controls,
    ErrorCode,
    ErrorMessage,
    LogEvent,
    Status,
    TaskName,
)
from app.core.exceptions import (
    MONGO_UNAVAILABLE_ERRORS,
    TEMPORARY_ERRORS,
    ControlsNotMapped,
    JobFailed,
    LeaseLost,
)
from app.data_access.jobs.work_control_repository import WorkControlRepository
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.scenario.controls import ControlMapper, controls_record
from app.domain.shared.parallel import run_in_parallel
from app.models.scenario.asset_context import FrozenContext
from app.realtime.publisher import publish_session_status
from app.search.service import LibrarySearch
from app.search.snapshot import LibrarySnapshot
from app.worker.celery_app import send_job
from app.worker.jobs import describe_outage, keep_lease_alive, outage_error

log = structlog.get_logger(__name__)


class ControlsJob:
    """Maps written scenarios' controls and requeues stalled mappings; long-lived, one per worker."""

    def __init__(
        self,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        work_control: WorkControlRepository,
        search: LibrarySearch,
        rerank: RerankModel,
    ) -> None:
        self._sessions, self._scenarios, self._work_control = sessions, scenarios, work_control
        self._search = search
        self._mapper = ControlMapper(rerank)  # holds no scenario's state: one for every delivery

    def map_threat_scenario_controls(self, record_id: str, task_id: str) -> int:
        """Take the run's delivery lease and map its waiting scenarios; how many were mapped (0 while another
        delivery holds the run)."""
        # Taken before anything is loaded, so a message that finds the run being mapped costs one update.
        claimed = self._sessions.claim_controls_delivery(record_id, task_id)
        if claimed is None:
            return 0
        if request_id := (claimed.get("job") or {}).get("request_id"):
            structlog.contextvars.bind_contextvars(request_id=request_id)  # a sweep's re-send carries none
        context, snapshot = claimed.get("context", {}), self._search.snapshot()
        return RunControls(
            record_id, task_id, context, self._sessions, self._scenarios, snapshot, self._mapper
        ).map_all()

    def note_controls_outage(
        self, record_id: str, task_id: str, exc: Exception, attempt: int, retry_in_seconds: int
    ) -> None:
        """Show a delivery's outage on its run's status until the next delivery claims the run: why, which
        try of the message, when the next comes. Nothing while another delivery holds the run or MongoDB is
        down."""
        notice = {
            "reason": outage_reason(exc),
            "message": describe_outage(exc),
            "attempt": attempt,
            "max_attempts": Controls.MAX_MESSAGE_RETRIES + 1,
            "retry_at": utc_now() + timedelta(seconds=retry_in_seconds),
        }
        with contextlib.suppress(*MONGO_UNAVAILABLE_ERRORS):
            if self._sessions.note_controls_retry(record_id, task_id, notice):
                publish_session_status(record_id)

    def retry_stalled_controls(self) -> None:
        """Sweep stalled mappings, recount and publish every run the sweep changed, then send one message per
        run they belong to that no delivery serves (read after the requeue, so a run released in between
        still gets its message)."""
        swept: dict[str, dict[str, int]] = {}

        def recount(session_id: str) -> None:
            counts = recount_and_publish(self._sessions, session_id)
            swept[session_id] = {key: value for key, value in counts.items() if key.startswith("controls_")}

        record_ids = self._work_control.sweep_stalled_controls(recount)
        if swept:
            log.info(LogEvent.CONTROLS_SWEPT, runs=swept, messages=len(record_ids))
        for record_id in record_ids:
            send_job(TaskName.MAP_CONTROLS, record_id, 0)  # the epoch is never checked for controls


def recount_and_publish(
    sessions: ThreatScenarioSessionRepository,
    session_id: str,
    controls_seconds: float = 0.0,
    card_queued_at: datetime | None = None,
) -> dict[str, int]:
    """Recount a run's counts and tell its watchers: the one path every controls change takes."""
    counts = sessions.update_scenario_session_counts(session_id, controls_seconds, card_queued_at)
    publish_session_status(session_id)
    return counts


class RunControls:
    """One delivery mapping one run's waiting scenarios, holding the run's delivery lease."""

    def __init__(
        self,
        record_id: str,
        task_id: str,
        context: dict[str, Any],
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        snapshot: LibrarySnapshot,
        mapper: ControlMapper,
    ) -> None:
        """`context`: the run's frozen context, as its delivery claim returned it."""
        self._record_id, self._task_id = record_id, task_id
        self._context = FrozenContext.from_record(context)
        self._sessions, self._scenarios = sessions, scenarios
        self._snapshot, self._mapper = snapshot, mapper
        self._taken_over = False  # another delivery took the run over mid-turn

    def map_all(self) -> int:
        """Map up to Controls.PER_DELIVERY scenarios, all at once on a remote reranker (the local CPU model
        predicts one at a time: one by one), updating the run's counts and watchers after each; a delivery
        that used its whole turn hands the run over and queues its next turn behind other work. A failure is
        raised once the scenarios beside it are saved."""
        at_once = Controls.PER_DELIVERY if get_settings().rerank_base_url else 1
        mapped = 0
        for _ in range(Controls.PER_DELIVERY // at_once):
            # Claimed before any is mapped: a scenario an outage gives back is never claimed again this turn.
            scenarios = self._claim_up_to(at_once)
            mapped += sum(run_in_parallel(self._map_and_count, scenarios, at_once, "controls"))
            if self._taken_over:  # the run's lease ran out mid-turn and another delivery took the run over
                return mapped
            if len(scenarios) < at_once:  # none waits: the run's mapping is done until its next written batch
                self._release()
                return mapped
        self._sessions.update_controls_delivery(self._record_id, self._task_id, hand_over=True)
        send_job(TaskName.MAP_CONTROLS, self._record_id, 0)  # the epoch is never checked for controls
        return mapped

    def _claim_up_to(self, count: int) -> list[dict[str, Any]]:
        """Up to `count` of the run's waiting scenarios, oldest first, claimed for this delivery."""
        claimed: list[dict[str, Any]] = []
        while len(claimed) < count:
            scenario = self._scenarios.claim_scenario_controls(self._record_id, self._task_id)
            if scenario is None:
                break
            claimed.append(scenario)
        return claimed

    def _map_and_count(self, scenario: dict[str, Any]) -> int:
        """Map one claimed scenario under the request and API call that wrote it (the run's job may be a later
        one's), then, mapped or failed, update the run's counts, watchers and lease: 1 when saved."""
        # None on a card written before they were stored.
        writer = {
            "request_id": scenario["controls"].get("request_id"),
            **(scenario["controls"].get("origin") or {}),
        }
        started = time.perf_counter()  # high resolution: monotonic ticks every ~16 ms on Windows
        # A context manager, not a bind: one scenario runs in the caller's context (run_in_parallel).
        with structlog.contextvars.bound_contextvars(
            **{name: value for name, value in writer.items() if value}
        ):
            try:
                return self._map_one(scenario)
            finally:
                seconds, queued_at = time.perf_counter() - started, scenario["controls"].get("queued_at")
                recount_and_publish(self._sessions, self._record_id, seconds, queued_at)
                if not self._sessions.update_controls_delivery(self._record_id, self._task_id):
                    self._taken_over = True

    def _release(self) -> None:
        """Give up the run's lease; a scenario written meanwhile, whose message found the run held, gets a
        message of its own instead of waiting for the sweep."""
        self._sessions.release_controls_delivery(self._record_id, self._task_id)
        if self._scenarios.count(session_id=self._record_id, controls_waiting=True):
            send_job(TaskName.MAP_CONTROLS, self._record_id, 0)

    def _map_one(self, scenario: dict[str, Any]) -> int:
        """Map and save one scenario's controls: 1 when saved. A reason no retry changes fails its controls;
        an outage gives it back and is raised; a job-wide failure fails it and is raised; a lost lease skips
        it."""
        scenario_id, attempts = scenario["_id"], scenario["controls"]["attempts"]
        try:
            lease = _ScenarioLease(
                self._sessions, self._scenarios, self._record_id, (scenario_id, attempts), self._task_id
            )
            # Background work: on a local CPU reranker any waiting foreground rerank goes first.
            with keep_lease_alive(lease, lease.give_back), background_reranks():
                mapping = self._mapper.map_controls(scenario, self._context, self._snapshot)
        except ControlsNotMapped as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            return 0
        except TEMPORARY_ERRORS as exc:
            self._scenarios.update_scenario_controls(
                scenario_id, self._task_id, attempts, Status.QUEUED, error=outage_error(exc)
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
        saved = self._scenarios.update_scenario_controls(
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
        self._scenarios.update_scenario_controls(
            scenario_id, self._task_id, attempts, Status.FAILED, error=error
        )


class _ScenarioLease:
    """One scenario's control lease as keep_lease_alive renews it, renewing the run's delivery lease too (a
    slow mapping must not let another delivery take the run over)."""

    def __init__(
        self,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        session_id: str,
        claim: tuple[str, int],
        task_id: str,
    ) -> None:
        """`claim`: the scenario id and the attempts its claim counted."""
        self._sessions, self._scenarios = sessions, scenarios
        self._session_id, (self.record_id, self._attempts), self._task_id = session_id, claim, task_id

    def renew(self) -> bool:
        """Renew the run's delivery lease and this scenario's lease; True while the scenario's holds."""
        self._sessions.update_controls_delivery(self._session_id, self._task_id)
        return self._scenarios.update_scenario_controls(
            self.record_id, self._task_id, self._attempts, Status.RUNNING
        )

    def give_back(self) -> bool:
        """For a stopping worker: the scenario queued again with its attempt returned, then the run's delivery
        lease freed and its next delivery sent (once per run); False once the scenario was taken over."""
        if not self._scenarios.update_scenario_controls(
            self.record_id, self._task_id, self._attempts, Status.QUEUED, attempt_returned=True
        ):
            return False
        log.info(LogEvent.JOB_HANDED_BACK, record_id=self.record_id, attempt=self._attempts)
        if self._sessions.release_controls_delivery(self._session_id, self._task_id):
            send_job(TaskName.MAP_CONTROLS, self._session_id, 0)  # the epoch is never checked for controls
        return True
