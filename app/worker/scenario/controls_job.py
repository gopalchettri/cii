"""The control mapping jobs: one delivery at a time maps a run's written scenarios."""

import contextlib
import threading
import time
from collections.abc import Callable
from concurrent import futures
from datetime import timedelta
from functools import partial
from typing import Any

import structlog

from app.ai import RerankModel
from app.ai.rerank import get_rerank_model
from app.core import constants as c
from app.core import exceptions
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.exceptions import outage_reason
from app.core.lease_signal import wait_while_leased
from app.crud import work_control
from app.crud.scenarios import get_threat_scenario_repository, get_threat_scenario_session_repository
from app.domain.scenario.attack_controls import is_attack_scenario, pick_set_controls
from app.domain.scenario.write import build_control_query, map_controls
from app.domain.shared.parallel import run_in_parallel
from app.realtime.publisher import publish_session_status
from app.schemas.scenario_internal import ControlQuery, FrozenContext
from app.search.service import get_library_search
from app.search.snapshot import LibrarySnapshot
from app.worker.celery_app import send_job
from app.worker.jobs import describe_outage, keep_lease_alive, outage_error

log = structlog.get_logger(__name__)


def map_threat_scenario_controls(record_id: str, task_id: str) -> int:
    """Take the run's delivery lease and map its waiting scenarios."""
    search, rerank = get_library_search(), get_rerank_model()
    claimed = get_threat_scenario_session_repository().claim_controls_delivery(record_id, task_id)
    if claimed is None:
        return 0
    if request_id := (claimed.get("job") or {}).get("request_id"):
        structlog.contextvars.bind_contextvars(request_id=request_id)  # a sweep's re-send carries none
    return RunControls(record_id, task_id, search.snapshot(), rerank).map_all()


def note_controls_outage(record_id: str, task_id: str, exc: Exception, attempt: int, retry_in_seconds: int) -> None:
    """Show a delivery's outage on its run's status until the next delivery claims the run."""
    notice = {
        "reason": outage_reason(exc),
        "message": describe_outage(exc),
        "attempt": attempt,
        "max_attempts": c.Controls.MAX_MESSAGE_RETRIES + 1,
        "retry_at": utc_now() + timedelta(seconds=retry_in_seconds),
    }
    with contextlib.suppress(*exceptions.MONGO_UNAVAILABLE_ERRORS):
        if get_threat_scenario_session_repository().note_controls_retry(record_id, task_id, notice):
            publish_session_status(record_id)


def retry_stalled_controls() -> None:
    """Sweep stalled mappings, recount and publish every run the sweep changed."""

    sessions, swept = get_threat_scenario_session_repository(), dict[str, dict[str, int]]()

    def recount(session_id: str) -> None:
        counts = sessions.update_scenario_session_counts(session_id)
        publish_session_status(session_id)
        swept[session_id] = {key: value for key, value in counts.items() if key.startswith("controls_")}

    record_ids = work_control.sweep_stalled_controls(recount)
    if swept:
        log.info(c.LogEvent.CONTROLS_SWEPT, runs=swept, messages=len(record_ids))
    for record_id in record_ids:
        send_job(c.TaskName.MAP_CONTROLS, record_id, 0)  # the epoch is never checked for controls


class RunControls:
    """One delivery mapping one run's waiting scenarios, holding the run's delivery lease."""

    _context: FrozenContext  # the run's frozen context, read when the first scenario is claimed

    def __init__(self, record_id: str, task_id: str, snapshot: LibrarySnapshot, rerank: RerankModel) -> None:
        self._record_id, self._task_id = record_id, task_id
        self._context_unread = True
        self._sessions, self._scenarios = get_threat_scenario_session_repository(), get_threat_scenario_repository()
        self._snapshot, self._rerank = snapshot, rerank
        self._taken_over = False  # another delivery took the run over mid-turn
        self._queries_embedded = _OneEmbedCall(lambda: None)  # the claimed scenarios' control queries
        self._queries: dict[str, ControlQuery] = {}  # each claimed scenario's control query, by its id
        self._picked: dict[str, dict[str, Any]] = {}  # the turn's ATT&CK-confirmed scenarios' records, by id

    def map_all(self) -> int:
        """Map up to Controls.PER_DELIVERY scenarios of the run, each under its own lease."""
        at_once = c.Controls.PER_DELIVERY if get_settings().rerank_base_url else 1
        mapped = 0
        for _ in range(c.Controls.PER_DELIVERY // at_once):
            scenarios = self._claim_up_to(at_once)
            self._queries_embedded = _OneEmbedCall(partial(self._embed_queries, scenarios))
            width = max(at_once, len(scenarios))  # a picked set is wider: each of its leases is kept alive
            mapped += sum(run_in_parallel(self._map_and_count, scenarios, width, "controls"))
            if self._taken_over:  # the run's lease ran out mid-turn and another delivery took the run over
                return mapped
            if len(scenarios) < at_once:  # none waits: the run's mapping is done until its next written batch
                self._sessions.release_controls_delivery(self._record_id, self._task_id)
                if self._scenarios.count(session_id=self._record_id, controls_waiting=True):
                    send_job(c.TaskName.MAP_CONTROLS, self._record_id, 0)
                return mapped
        self._sessions.update_controls_delivery(self._record_id, self._task_id, hand_over=True)
        send_job(c.TaskName.MAP_CONTROLS, self._record_id, 0)  # the epoch is never checked for controls
        return mapped

    def _embed_queries(self, scenarios: list[dict[str, Any]]) -> None:
        if not self._snapshot.library.control_library:  # nothing to search: each mapping fails with no call
            return
        self._picked = self._pick_set([scenario for scenario in scenarios if is_attack_scenario(scenario)])
        searched = [scenario for scenario in scenarios if not is_attack_scenario(scenario)]
        self._queries = {
            scenario["_id"]: build_control_query(scenario["content"], self._context) for scenario in searched
        }
        if searched:
            self._snapshot.embed_control_queries([query.text for query in self._queries.values()])

    def _pick_set(self, scenarios: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """The ATT&CK-confirmed scenarios' controls records by id, in one AI call; {}: the search maps them."""
        try:
            return pick_set_controls(self._rerank, scenarios, self._context, self._snapshot)
        except exceptions.TEMPORARY_ERRORS:
            raise
        except exceptions.LeaseLost:
            raise
        except Exception:  # the picker's fault must not cost the set its controls
            log.exception(c.LogEvent.CONTROLS_PICK_UNUSABLE, record_id=self._record_id)
            return {}

    def _claim_up_to(self, count: int) -> list[dict[str, Any]]:
        claimed: list[dict[str, Any]] = []
        while len(claimed) < count:
            scenario = self._scenarios.claim_scenario_controls(self._record_id, self._task_id)
            if scenario is None:
                break
            claimed.append(scenario)
            if is_attack_scenario(scenario):  # picked as one set in one AI call, whatever the reranker takes
                count = c.Controls.PER_DELIVERY
        if claimed and self._context_unread:  # one read, and none for a delivery with nothing to map
            try:
                context = self._sessions.get_scenario_session_context(self._record_id)
            except exceptions.NotFound:  # the run was deleted meanwhile: its scenarios go with it
                return []
            self._context, self._context_unread = FrozenContext.from_record(context), False
        return claimed

    def _map_and_count(self, scenario: dict[str, Any]) -> int:
        writer = {"request_id": scenario["controls"].get("request_id"), **(scenario["controls"].get("origin") or {})}
        started = time.perf_counter()  # high resolution: monotonic ticks every ~16 ms on Windows
        with structlog.contextvars.bound_contextvars(**{name: value for name, value in writer.items() if value}):
            try:
                return self._map_one(scenario)
            finally:
                seconds, queued_at = time.perf_counter() - started, scenario["controls"].get("queued_at")
                sharing = len(self._picked) if scenario["_id"] in self._picked else 1  # a set's one call: once
                self._sessions.update_scenario_session_counts(self._record_id, seconds / sharing, queued_at)
                publish_session_status(self._record_id)
                if not self._sessions.update_controls_delivery(self._record_id, self._task_id):
                    self._taken_over = True

    def _map_one(self, scenario: dict[str, Any]) -> int:
        scenario_id, attempts = scenario["_id"], scenario["controls"]["attempts"]
        try:
            renew = partial(self._renew, scenario_id, attempts)
            with keep_lease_alive(scenario_id, renew, partial(self._give_back, scenario_id, attempts)):
                self._queries_embedded.wait()  # under this scenario's lease: the call may be slow
                query = self._queries.get(scenario_id)
                mapping = self._picked.get(scenario_id)  # an ATT&CK-confirmed scenario: picked with its set
                if mapping is None:
                    mapping = map_controls(self._rerank, scenario, self._context, self._snapshot, query)
        except exceptions.ControlsNotMapped as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            return 0
        except exceptions.TEMPORARY_ERRORS as exc:
            self._scenarios.update_scenario_controls(
                scenario_id, self._task_id, attempts, c.Status.QUEUED, error=outage_error(exc)
            )
            raise
        except exceptions.JobFailed as exc:
            self._fail(scenario_id, attempts, exc.code, exc.message)
            raise
        except exceptions.LeaseLost as exc:  # its run was cancelled, or another delivery took the scenario over
            if str(exc) != scenario_id:  # the set's one call stopped on another scenario's lease: mapped next turn
                self._scenarios.update_scenario_controls(
                    scenario_id, self._task_id, attempts, c.Status.QUEUED, attempt_returned=True
                )
            return 0
        except Exception:  # one scenario's fault must not cost the run its other scenarios
            log.exception(c.LogEvent.CONTROLS_MAP_FAILED, scenario_id=scenario_id)
            message = c.ErrorMessage.JOB_UNEXPECTED.format(record_id=self._record_id)
            self._fail(scenario_id, attempts, c.ErrorCode.INTERNAL_ERROR, message)
            return 0
        saved = self._scenarios.update_scenario_controls(
            scenario_id, self._task_id, attempts, c.Status.DONE, mapping=mapping
        )
        log.info(c.LogEvent.CONTROLS_MAPPED, scenario_id=scenario_id, controls=len(mapping["items"]), saved=saved)
        return int(saved)

    def _fail(self, scenario_id: str, attempts: int, code: str, message: str) -> None:
        log.warning(c.LogEvent.CONTROLS_NOT_MAPPED, scenario_id=scenario_id, code=code)
        error = {"code": code, "message": message}
        self._scenarios.update_scenario_controls(scenario_id, self._task_id, attempts, c.Status.FAILED, error=error)

    def _renew(self, scenario_id: str, attempts: int) -> bool:
        """Renew the run's delivery lease and the scenario's lease; True while the scenario's holds."""
        self._sessions.update_controls_delivery(self._record_id, self._task_id)
        return self._scenarios.update_scenario_controls(scenario_id, self._task_id, attempts, c.Status.RUNNING)

    def _give_back(self, scenario_id: str, attempts: int) -> bool:
        """For a stopping worker: queue the scenario again and free the run's delivery lease."""
        if not self._scenarios.update_scenario_controls(
            scenario_id, self._task_id, attempts, c.Status.QUEUED, attempt_returned=True
        ):
            return False
        log.info(c.LogEvent.JOB_HANDED_BACK, record_id=scenario_id, attempt=attempts)
        if self._sessions.release_controls_delivery(self._record_id, self._task_id):
            send_job(c.TaskName.MAP_CONTROLS, self._record_id, 0)  # the epoch is never checked for controls
        return True


class _OneEmbedCall:
    """A turn's control queries embedded in one call by the first of its mappings to ask."""

    def __init__(self, embed: Callable[[], None]) -> None:
        self._embed, self._lock = embed, threading.Lock()
        self._outcome: futures.Future[Exception | None] | None = None  # the outage the call met, if any

    def wait(self) -> None:
        """Embed on the first call; the others wait checking their own lease."""
        with self._lock:
            first = self._outcome is None
            outcome = self._outcome = self._outcome or futures.Future()
        if first:
            try:
                outcome.set_result(self._embed_or_outage())
            except BaseException as exc:  # an interrupt too: no waiter waits for ever
                outcome.set_exception(exc)
                raise
        if (outage := wait_while_leased(outcome)) is not None:
            raise outage

    def _embed_or_outage(self) -> Exception | None:
        try:
            self._embed()
        except exceptions.TEMPORARY_ERRORS as exc:
            return exc
        except exceptions.LeaseLost:  # the set was not picked: no waiter maps its scenario by the search
            raise
        except Exception:  # noqa: BLE001 - each scenario's own search meets it and settles it
            return None
        return None
