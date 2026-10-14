"""Scenario writing (Step 12, BUILD_PLAN S25-S26). tsg_write_scenarios writes one batch of the set a person
asked for (the run's first set, or a "next set" call: owner 2026-10-11), up to Generation.WRITER_BATCH at
once, and saves each scenario the moment it is done; then it hands the set's next batch to itself, or ends the
set, in one fenced write (app/worker/plan_progress.py).

Per path: an unreadable answer gives a visible failure card and a remaining blocker a hidden one; either
way the path is tried again in a later batch, and abandoned after Generation.MAX_PATH_ATTEMPTS. A path the
frozen plan cannot support is abandoned at once. An AI or store outage gives the whole job back once the other
paths are saved; the retry skips every path already written. A batch naming the versions it `replaces` is a
regenerate (#6): app/worker/regenerator.py writes it, then the run ends.

With external intelligence on, a batch's scenarios are written as evidence stories and the batch first
searches the evidence of its own threats, once (app/worker/external_intelligence/evidence_at_write.py);
with it off the original writer runs, exactly as before."""

import dataclasses
from functools import partial
from typing import Any

import structlog
from celery import Task
from pymongo.database import Database

from app.ai import ChatModel, get_chat_model
from app.core import metrics
from app.core.constants import (
    Collection,
    ErrorCode,
    ErrorMessage,
    Generation,
    Lease,
    LogEvent,
    ScenarioOutcome,
    ScenarioStatus,
    TaskName,
    WriterStyle,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.core.tracing import traced
from app.data_access.job_records import JobLease
from app.data_access.run_counts import RunCounts
from app.data_access.scenarios import ScenarioRepository, find_finished
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.writing.evidence_gate import evidence_problem
from app.engine.scenarios.writing.near_copies import near_copy
from app.engine.scenarios.writing.scenario_record import failure_record, written_record
from app.engine.shared.parallel import raise_most_retryable
from app.models.library import ThreatLibrary
from app.models.writing import PathFailure, WriterBrief, WrittenScenario
from app.search.library_cache import get_library_service
from app.worker.celery_app import celery_app, send_job
from app.worker.external_intelligence.evidence_at_write import EvidenceAtWrite
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access
from app.worker.jobs import run_leased_job
from app.worker.path_writing import PathOutcome, PathWriter, save_with_unique_title, write_at_once
from app.worker.plan_progress import PlanProgress
from app.worker.regenerator import Regenerator

log = structlog.get_logger(__name__)

#: tsg_scenarios_total's outcome for each saved status.
_OUTCOMES = {
    ScenarioStatus.DONE: ScenarioOutcome.WRITTEN,
    ScenarioStatus.BLOCKED: ScenarioOutcome.BLOCKED,
    ScenarioStatus.FAILED: ScenarioOutcome.FAILED,
}


@celery_app.task(name=TaskName.WRITE_SCENARIOS, bind=True)
def write_scenarios(self: Task, record_id: str, epoch: int) -> None:
    run_leased_job(self, Collection.SESSIONS, record_id, epoch, write_batch)


@traced("worker.write_batch")
def write_batch(lease: JobLease) -> None:
    db = get_mongodb()
    run = SessionRepository(db).find_for_writing(lease.record_id)
    library = get_library_service().get_threat_library()  # in memory; reloaded within a minute of an edit
    if any(item.get("replaces") for item in run["job"].get("batch") or []):  # regenerate (#6)
        Regenerator(lease, run, db, get_chat_model(), library).regenerate()
    else:
        BatchWriter(lease, run, db, get_chat_model(), library).write()


class BatchWriter:
    """One delivery's batch: its paths written at once, each saved as soon as it is done; then the set's next
    batch is handed over, or the set ends."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        db: Database,
        chat: ChatModel,
        library: ThreatLibrary,
        access: IntelAccess | None = None,
    ) -> None:
        self._lease, self._run, self._scenarios = lease, run, ScenarioRepository(db)
        self._progress = PlanProgress(lease, run, self._scenarios, RunCounts(db))
        access = access or get_intel_access()
        self._style = (
            access.writer_style()
        )  # decided once per batch: ORIGINAL while external intelligence is off
        self._paths = PathWriter(run, chat, library, self._style)
        self._evidence = EvidenceAtWrite(run, self._paths.threats, self._progress, access)
        self._evidence_waits: set[str] = set()  # paths held back by an evidence search outage (G229)
        self._db = db
        self._finished: list[dict[str, Any]] | None = None  # the run's finished scenarios, read once (G229)

    def write(self) -> None:
        paths = self._progress.paths
        batch = [item["path_id"] for item in self._run["job"].get("batch") or [] if item["path_id"] in paths]
        open_paths = [path_id for path_id in batch if self._progress.is_still_to_write(path_id)]
        written = self._scenarios.find_written(self._run["_id"], open_paths)
        if written:  # an earlier delivery wrote them: no AI call again, one write for all
            self._progress.record(
                {path_id: {"served": scenario_id} for path_id, scenario_id in written.items()}
            )
        to_write = [path_id for path_id in open_paths if self._progress.is_still_to_write(path_id)]
        outages: dict[str, BaseException] = {}
        if self._style is WriterStyle.EVIDENCE_STORY:
            self._evidence.attach(to_write)  # only now, only for these paths: one search for the batch
            to_write = [path_id for path_id in to_write if not self._held_back(path_id, outages)]
        outages |= self._write_all(to_write)
        if outages:
            self._settle_outages(batch, outages)
        # "Card first, controls later": reviewers see scenarios while they are mapped. Sent for every written
        # scenario of the batch, whichever delivery wrote it: one that died after saving and before this line
        # must not leave its controls to the sweep. A repeat is harmless (the controls job claims each once).
        if any(self._progress.paths[path_id]["served"] for path_id in batch):
            send_job(TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        self._progress.continue_or_finish()

    def _held_back(self, path_id: str, outages: dict[str, BaseException]) -> bool:
        """G229: a story path whose threat has no usable evidence fails for good here, with no write call; one
        whose search could not be made waits as an outage (its own reason kept for its card)."""
        steps = self._progress.paths[path_id].get("steps") or []
        problem = evidence_problem(self._paths.threats[steps[0]]) if steps else None
        if isinstance(problem, PathFailure):
            self._save(path_id, problem)
        elif problem is not None:
            outages[path_id] = problem
            self._evidence_waits.add(path_id)
        return problem is not None

    def _write_all(self, path_ids: list[str]) -> dict[str, BaseException]:
        """Every path's AI work at once, each saved the moment it is done; the outages by path, for after."""
        work = {path_id: partial(self._paths.write, self._progress.paths[path_id]) for path_id in path_ids}
        return write_at_once(work, self._save)

    def _settle_outages(self, batch: list[str], outages: dict[str, BaseException]) -> None:
        """An outage gives the job back (raised). On its last try, when another path of the batch was written,
        the outage is these paths' own (a brief the model keeps timing out on): each gets a failure card and
        an attempt, and the run goes on. Without that evidence the provider is down: the run fails, as
        before."""
        errors = list(outages.values())
        own = (
            self._lease.attempts >= Lease.MAX_ATTEMPTS
            and all(isinstance(error, Unavailable) for error in errors)
            and any(self._progress.paths[path_id]["served"] for path_id in batch if path_id not in outages)
        )
        if not own:
            raise_most_retryable(errors)
        log.warning(LogEvent.WRITER_OUTAGE_SETTLED, paths=list(outages), attempts=self._lease.attempts)
        message = ErrorMessage.PATH_AI_UNAVAILABLE.format(tries=self._lease.attempts)
        for path_id, error in outages.items():  # an evidence outage keeps its own reason (G229)
            reason = str(error) if path_id in self._evidence_waits else message
            self._save(path_id, PathFailure(ErrorCode.UNAVAILABLE, reason))

    def _save(self, path_id: str, outcome: PathOutcome) -> None:
        """One path's outcome saved, then its state on the plan; in the job's own thread, one at a time."""
        self._progress.hold()
        path = self._progress.paths[path_id]
        if isinstance(outcome, PathFailure):
            steps = path.get("steps") or []
            threat = self._paths.threats.get(steps[0]) if len(steps) == 1 else None
            record = failure_record(self._run, path, threat, outcome)
            saved, tried_again, final = self._scenarios.save(record), True, outcome.final
            reason = str(outcome.code)
        else:
            record, saved, written = self._save_written(path, *outcome)
            tried_again, final = written.blocked, written.final  # G229: a final rule gives the path up
            reason = written.blocker
        log.info(LogEvent.WRITER_SCENARIO_SAVED, path_id=path_id, status=record["status"], saved=saved)
        if saved:
            metrics.SCENARIOS.labels(_OUTCOMES[record["status"]]).inc()
        if not saved or not tried_again:  # not saved: its written scenario was already there (same id)
            self._progress.record({path_id: {"served": record["_id"]}})
            return
        state = {"attempts": path["attempts"] + 1}
        if not (final or state["attempts"] >= Generation.MAX_PATH_ATTEMPTS):
            self._progress.record({path_id: state | {"abandoned": False}})
            return
        log.warning(LogEvent.WRITER_PATH_ABANDONED, path_id=path_id, attempts=state["attempts"])
        metrics.SCENARIOS.labels(ScenarioOutcome.ABANDONED).inc()
        evidence = self._style is WriterStyle.EVIDENCE_STORY  # G229: a reserve may take its place
        self._progress.abandon(path_id, state | {"abandoned": True}, reason, self._paths.threats, evidence)

    def _save_written(
        self, path: dict[str, Any], brief: WriterBrief, written: WrittenScenario
    ) -> tuple[dict[str, Any], bool, WrittenScenario]:
        """A written scenario saved, checked first against the run's finished ones (G229): a near copy is kept
        hidden, final, with the scenario it copies named."""
        threat = self._paths.threats[path["steps"][0]]
        record = written_record(self._run, path, threat, brief, written)
        if not written.blocked and (copy := near_copy(record["content"], self._finished_besides(path))):
            written = dataclasses.replace(written, findings=(*written.findings, copy))
            record = written_record(self._run, path, threat, brief, written)
        saved = save_with_unique_title(self._scenarios, record, written.title_qualifier)
        if saved and record["status"] == ScenarioStatus.DONE and self._finished is not None:
            self._finished.append(
                {"_id": record["_id"], "path_id": path["path_id"], "content": record["content"]}
            )
        return record, saved, written

    def _finished_besides(self, path: dict[str, Any]) -> list[dict[str, Any]]:
        """The run's finished scenarios but this path's own versions, read once per delivery."""
        if self._finished is None:
            self._finished = find_finished(self._db, self._run["_id"])
        return [item for item in self._finished if item.get("path_id") != path["path_id"]]
