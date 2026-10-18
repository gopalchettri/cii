"""The scenario write job: one batch of a run's paths written at once, each saved as soon as it is done, then
the set's next batch handed over, the set ended, or the regenerate ended."""

import contextvars
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from functools import partial
from typing import Any

import structlog
from celery import Task
from pymongo.database import Database

from app.ai import ChatModel, get_chat_model
from app.core.constants import (
    Collection,
    ErrorCode,
    ErrorMessage,
    Generation,
    Lease,
    LogEvent,
    SessionMessage,
    TaskName,
    WriterStyle,
)
from app.core.database import get_mongodb
from app.core.exceptions import NotFound, Unavailable
from app.data_access.jobs.repository import JobLease
from app.data_access.scenario.repository import scenario_sessions
from app.domain.scenario.write import evidence_problem
from app.domain.shared.parallel import raise_most_retryable
from app.models.library import ThreatLibrary
from app.models.scenario.write import PathFailure
from app.search.library_cache import get_library_service
from app.worker.celery_app import celery_app, send_job
from app.worker.external_intelligence.evidence_at_write import EvidenceAtWrite
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access
from app.worker.jobs import run_leased_job
from app.worker.path_writing import PathOutcome, PathSaver, PathWriter
from app.worker.plan_progress import PlanProgress

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.WRITE_SCENARIOS, bind=True)
def write_scenarios(self: Task, record_id: str, epoch: int) -> None:
    """Celery task: write the run's current batch under the run's job lease."""
    run_leased_job(self, Collection.SESSIONS, record_id, epoch, write_batch)


def write_batch(lease: JobLease) -> None:
    """Load the run, the chat model and the threat library, then write the batch."""
    db = get_mongodb()
    run = scenario_sessions.get(fields="writing", _id=lease.record_id)
    if run is None:  # deleted since the claim
        raise NotFound(SessionMessage.NOT_FOUND.format(session_id=lease.record_id))
    library = get_library_service().get_threat_library()  # in memory; reloaded within a minute of an edit
    BatchWriter(lease, run, db, get_chat_model(), library).write()


class BatchWriter:
    """One delivery's batch: its paths written at once and saved one by one, then the run moved on."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        db: Database,
        chat: ChatModel,
        library: ThreatLibrary,
        access: IntelAccess | None = None,
    ) -> None:
        access = access or get_intel_access()
        # A switch in doubt raises Unavailable, so the job is retried: no story without its evidence.
        self._story = access.is_on(sure=True)
        style = WriterStyle.EVIDENCE_STORY if self._story else WriterStyle.ORIGINAL
        self._lease, self._run = lease, run
        self._progress = PlanProgress(lease, run)
        self._paths = PathWriter(run, chat, library, style)
        self._saver = PathSaver(lease, run, self._progress, self._paths.threats, self._story)
        self._evidence = EvidenceAtWrite(run, self._paths.threats, self._progress, access)
        items = [item for item in run["job"].get("batch") or [] if item["path_id"] in self._progress.paths]
        self._batch = [item["path_id"] for item in items]
        self._replaces = {item["path_id"]: item["replaces"] for item in items if item.get("replaces")}
        self._evidence_waits: set[str] = set()  # paths held back by an evidence search outage

    def write(self) -> None:
        """Write the batch's open paths, settle any outage, queue control mapping, then move the run on."""
        to_write = self._saver.to_write(self._batch, self._replaces)
        outages: dict[str, BaseException] = {}
        if self._story:
            self._evidence.attach(to_write)  # one evidence search for the paths about to be written
            to_write = {key: others for key, others in to_write.items() if not self._held_back(key, outages)}
        paths = self._progress.paths
        path_jobs = {key: partial(self._paths.write, paths[key], others) for key, others in to_write.items()}
        outages |= write_at_once(path_jobs, self._saver.save)
        if outages:
            self._settle_outages(outages)
        # Sent for every scenario of the batch, whichever delivery saved it: a delivery that died after
        # saving must not leave its controls to the sweep. The controls job claims each scenario once.
        if self._served_paths():
            send_job(TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        if self._replaces:
            self._progress.finish_regenerate(len(self._served_paths()), len(self._replaces))
        else:
            self._progress.continue_or_finish()

    def _served_paths(self) -> list[str]:
        """The batch's paths served by a scenario written for it (a regenerate's: a new version)."""
        paths = self._progress.paths
        return [key for key in self._batch if paths[key]["served"] not in (None, self._replaces.get(key))]

    def _held_back(self, path_id: str, outages: dict[str, BaseException]) -> bool:
        """Hold a story back when its threat has no usable evidence: a final failure is saved now with no
        write call, a search that could not be made waits as an outage."""
        steps = self._progress.paths[path_id].get("steps") or []
        problem = evidence_problem(self._paths.threats[steps[0]]) if steps else None
        if isinstance(problem, PathFailure):
            self._saver.save(path_id, problem)
        elif problem is not None:
            outages[path_id] = problem
            self._evidence_waits.add(path_id)
        return problem is not None

    def _settle_outages(self, outages: dict[str, BaseException]) -> None:
        """Give the job back (raise), unless this is its last try and the provider answered the batch's other
        paths (or it is a regenerate): then each of these paths gets its failure and the job goes on."""
        errors = list(outages.values())
        paths_own_outage = (
            self._lease.attempts >= Lease.MAX_ATTEMPTS
            and all(isinstance(error, Unavailable) for error in errors)
            and (bool(self._replaces) or bool(self._served_paths()))
        )
        if not paths_own_outage:
            raise_most_retryable(errors)
        log.warning(LogEvent.WRITER_OUTAGE_SETTLED, paths=list(outages), attempts=self._lease.attempts)
        message = ErrorMessage.PATH_AI_UNAVAILABLE.format(tries=self._lease.attempts)
        for path_id, error in outages.items():  # an evidence outage keeps its own reason
            reason = str(error) if path_id in self._evidence_waits else message
            self._saver.save(path_id, PathFailure(ErrorCode.UNAVAILABLE, reason))


def write_at_once(
    jobs: Mapping[str, Callable[[], PathOutcome]], save: Callable[[str, PathOutcome, datetime], None]
) -> dict[str, BaseException]:
    """Run every path's AI work in a thread pool and `save` each outcome in this thread as it finishes, with
    when its work began; return the outages by path, raised by none."""
    outages: dict[str, BaseException] = {}
    if not jobs:
        return outages
    with ThreadPoolExecutor(min(Generation.WRITER_BATCH, len(jobs)), thread_name_prefix="writer") as pool:
        # Each job runs in its own copy of this thread's context, so its log lines keep the run's fields.
        futures = {
            pool.submit(contextvars.copy_context().run, _run_timed, job): key for key, job in jobs.items()
        }
        try:
            for future in as_completed(futures):
                if (error := future.exception()) is not None:
                    outages[futures[future]] = error
                else:
                    started, outcome = future.result()
                    save(futures[future], outcome, started)
        except BaseException:  # a lost lease or a store outage: the paths not started are not started
            for future in futures:
                future.cancel()
            raise
    return outages


def _run_timed(job: Callable[[], PathOutcome]) -> tuple[datetime, PathOutcome]:
    """Run `job`; return when it started and its outcome."""
    started = datetime.now(UTC)
    return started, job()
