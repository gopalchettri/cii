"""A plan request's control top-up. A plan never starts without a
control, so a request whose accepted scenario has none maps them itself, under the scenario's
own control lease: a worker and a request never map one scenario at once. The request waits
Remediation.TOP_UP_SECONDS at most; past that, or on an outage, the controls go back to the controls job
and the answer is 503 controls_not_ready with Retry-After. A late result is never saved: only the request
thread writes, and only within its deadline."""

import contextvars
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import structlog
from pymongo.database import Database

from app.ai import ai_deadline, get_rerank_model
from app.core.constants import (
    ConflictReason,
    ErrorCode,
    LogEvent,
    Remediation,
    RemediationMessage,
    RunKind,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict, ControlsNotMapped, Unavailable
from app.data_access.run_counts import RunCounts
from app.data_access.scenario_controls import ControlLeases
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.control_mapper import ControlMapper, controls_record
from app.models.asset_context import FrozenContext
from app.realtime.publisher import publish_session_status
from app.search.service import LibrarySearch, get_library_search
from app.worker.celery_app import send_job
from app.worker.jobs import TEMPORARY_ERRORS, describe_outage

log = structlog.get_logger(__name__)

#: ponytail: one pool per API process at the default size (min(32, CPUs + 4)); a top-up beyond it waits its
#: turn inside its own deadline. A mapping past its deadline ends with it: its AI calls share the deadline.
_POOL = ThreadPoolExecutor(thread_name_prefix="controls-top-up")


class ControlsTopUp:
    def __init__(
        self,
        db: Database,
        mapper: ControlMapper,
        library: LibrarySearch,
        deadline_seconds: float = Remediation.TOP_UP_SECONDS,
    ) -> None:
        self._leases, self._sessions, self._counts = ControlLeases(db), SessionRepository(db), RunCounts(db)
        self._mapper, self._library, self._deadline = mapper, library, deadline_seconds

    def map_now(self, scenario_id: str, remap: bool = False) -> list[dict[str, Any]]:
        """The scenario's mapped controls (their records), mapped in this request when they were not. Conflict
        when no control can fit (an empty library, none compatible: a retry cannot change that); Unavailable
        `controls_not_ready` when a worker maps them now, the deadline passed, or a store or AI service is
        down. `remap`: mapped already, but every control was retired since: mapped again."""
        started = time.monotonic()
        task_id = f"{_request_id()}:{uuid.uuid4().hex}"  # unique: a lease's owner is never shared
        claimed = self._leases.claim_scenario(scenario_id, task_id, remap)
        if claimed is None:  # a worker holds them, or they were mapped since the caller read the scenario
            if not remap and (items := self._leases.find_mapped(scenario_id)) is not None:
                return items
            raise _not_ready()
        try:
            mapped = self._mapped_within_deadline(claimed, started)
        except ControlsNotMapped as exc:
            self._leases.fail(scenario_id, task_id, {"code": exc.code, "message": exc.message})
            self._settle(claimed)
            raise Conflict(exc.message, reason=exc.code) from exc
        except TimeoutError as exc:
            late = RemediationMessage.TOP_UP_LATE.format(seconds=self._deadline)
            self._give_back(claimed, task_id, late)
            raise _not_ready() from exc
        except TEMPORARY_ERRORS as exc:
            self._give_back(claimed, task_id, describe_outage(exc))
            raise _not_ready() from exc
        except Exception as exc:
            self._give_back(claimed, task_id, type(exc).__name__)
            raise
        if not self._leases.finish(scenario_id, task_id, mapped):
            raise _not_ready()
        self._settle(claimed, time.monotonic() - started)
        log.info(LogEvent.CONTROLS_TOPPED_UP, scenario_id=scenario_id, controls=len(mapped["items"]))
        return mapped["items"]

    def _mapped_within_deadline(self, claimed: dict[str, Any], started: float) -> dict[str, Any]:
        """The mapping record, from a pool thread the request waits for until its deadline (TimeoutError
        after it). Its AI calls end by the same deadline (R1T step 2): none keeps running, holding an AI slot,
        for a request that has gone."""
        context = FrozenContext.from_record(self._sessions.find_context(claimed["session_id"]))
        until = started + self._deadline
        future = _POOL.submit(contextvars.copy_context().run, self._map, claimed, context, until)
        try:
            return future.result(timeout=max(0.0, until - time.monotonic()))
        except TimeoutError:
            future.cancel()  # still waiting behind other top-ups: never run for a request that has gone
            raise

    def _map(self, claimed: dict[str, Any], context: FrozenContext, until: float) -> dict[str, Any]:
        snapshot = (
            self._library.snapshot()
        )  # built once per API process, for every later request: no deadline
        with ai_deadline(until):
            return controls_record(self._mapper.map_controls(claimed, context, snapshot), snapshot)

    def _give_back(self, claimed: dict[str, Any], task_id: str, reason: str) -> None:
        """A generated scenario's controls back to the controls job, sent now rather than at the next sweep; a
        hand-written one's failed: the background never maps it (Rule R1T step 4)."""
        scenario_id, error = claimed["_id"], {"code": ErrorCode.UNAVAILABLE, "message": reason}
        log.warning(LogEvent.CONTROLS_TOP_UP_GIVEN_BACK, scenario_id=scenario_id, reason=reason)
        if claimed.get("source") == RunKind.MANUAL:
            self._leases.fail(scenario_id, task_id, error)
        else:
            self._leases.give_back(scenario_id, task_id, claimed["controls"]["attempts"], error)
            send_job(
                TaskName.MAP_CONTROLS, claimed["session_id"], 0
            )  # the epoch is never checked for controls
        self._settle(claimed)

    def _settle(self, claimed: dict[str, Any], controls_seconds: float = 0.0) -> None:
        """The run's counts and its watchers after one of its scenarios' controls changed state: a failed one
        no longer waits, so the run must stop reading step "controls". `controls_seconds`: a mapping's time,
        added to the run's controls time."""
        self._counts.refresh(claimed["session_id"], controls_seconds)
        publish_session_status(claimed["session_id"])


def get_controls_top_up() -> ControlsTopUp:
    return ControlsTopUp(get_mongodb(), ControlMapper(get_rerank_model()), get_library_search())


def _request_id() -> str:
    return str(structlog.contextvars.get_contextvars().get("request_id") or "none")


def _not_ready() -> Unavailable:
    seconds = Remediation.TOP_UP_RETRY_AFTER_SECONDS
    message = RemediationMessage.CONTROLS_NOT_READY.format(seconds=seconds)
    return Unavailable(message, reason=ConflictReason.CONTROLS_NOT_READY, retry_after=seconds)
