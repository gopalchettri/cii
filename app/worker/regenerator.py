"""Regenerate (#6; BUILD_PLAN S41; BLUEPRINT Rule S7, R-8): a new version of each chosen scenario, written
as a path's first scenario is (app/worker/path_writing.py) and told to differ from the path's other versions;
then the run ends, complete when every target got its new version, partial when any kept its old one.

Version n stays current until version n+1 is saved; only then is n superseded, so a crash in between leaves
both current for a moment, never neither, and the retry only supersedes. A regenerate that writes nothing new
keeps n current with its reason (`regenerate_error`). The path's attempts count first writes only."""

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from functools import partial
from typing import Any

import structlog
from pymongo.database import Database

from app.ai import ChatModel
from app.core import metrics
from app.core.constants import (
    ErrorCode,
    ErrorMessage,
    FindingSeverity,
    Lease,
    LogEvent,
    RunActionOutcome,
    ScenarioOutcome,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.job_records import JobLease
from app.data_access.run_counts import RunCounts
from app.data_access.scenario_versions import ScenarioVersions
from app.data_access.scenarios import ScenarioRepository
from app.engine.scenarios.writing.scenario_record import scenario_id, written_record
from app.engine.shared.parallel import raise_most_retryable
from app.models.library import ThreatLibrary
from app.models.writing import PathFailure
from app.worker.celery_app import send_job
from app.worker.path_writing import PathOutcome, PathWriter, save_with_unique_title, write_at_once
from app.worker.plan_progress import PlanProgress

log = structlog.get_logger(__name__)


class Regenerator:
    """One regenerate delivery: each target's next version written at once, each saved once it is done."""

    def __init__(
        self, lease: JobLease, run: dict[str, Any], db: Database, chat: ChatModel, library: ThreatLibrary
    ) -> None:
        self._lease, self._run = lease, run
        self._scenarios, self._versions = ScenarioRepository(db), ScenarioVersions(db)
        self._progress = PlanProgress(lease, run, self._scenarios, RunCounts(db))
        self._paths = PathWriter(run, chat, library)
        self._targets = {item["replaces"]: item["path_id"] for item in run["job"]["batch"]}
        self._current: dict[str, dict[str, Any]] = {}  # each target still to replace: its version record
        self._done: set[str] = set()

    def regenerate(self) -> None:
        outages = write_at_once(self._heal_saved_and_list_work(), self._save)
        if outages:
            self._settle_outages(outages)
        if self._done:  # "card first, controls later"; a repeat message finds nothing to claim (G147)
            send_job(TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        complete = self._done.issuperset(self._targets)
        outcome = RunActionOutcome.COMPLETE if complete else RunActionOutcome.PARTIAL
        # What the status shows of it, with its own writing time (from the click, never from the plan).
        started = (self._run.get("last_action") or {}).get("started_at") or datetime.now(UTC)
        replaced = len(self._done & self._targets.keys())
        self._lease.finish(
            {
                "last_action.outcome": outcome,
                "last_regen": {"outcome": outcome, "requested": len(self._targets), "replaced": replaced},
                "timings.scenarios_s": round((datetime.now(UTC) - started).total_seconds(), 1),
            }
        )

    def _heal_saved_and_list_work(self) -> dict[str, Callable[[], PathOutcome]]:
        """Heals, then lists: a target whose next version an earlier delivery saved is finished here with no
        AI call, wherever that delivery stopped (superseded if it was not, its path served: G147); the
        targets still to write are returned."""
        versions = self._versions.find_versions(self._run["_id"], sorted(set(self._targets.values())))
        by_id = {row["_id"]: row for row in versions}
        statements: defaultdict[str, list[str]] = defaultdict(list)
        for row in versions:  # oldest first: the writer differs from every version, the newest kept first
            statements[row["path_id"]].append(row["content"]["statement"])
        work: dict[str, Callable[[], PathOutcome]] = {}
        healed: dict[str, dict[str, Any]] = {}
        for target_id, path_id in self._targets.items():
            target = by_id.get(target_id)
            if target is None:  # no longer a written version (the API checked it was): nothing to replace
                continue
            successor = target["superseded_by"] or scenario_id(
                self._run["_id"], path_id, target["version"] + 1
            )
            if target["superseded_by"] or successor in by_id:  # an earlier delivery wrote it, maybe crashed
                if not target["superseded_by"]:
                    self._versions.supersede(target_id, successor)
                self._done.add(target_id)
                if self._progress.paths[path_id]["served"] != successor:
                    healed[path_id] = {"served": successor}
                continue
            self._current[target_id] = target
            path = self._progress.paths[path_id]
            work[target_id] = partial(self._paths.write, path, tuple(statements[path_id]))
        if healed:  # a crash before the path's fenced write (G147): served, counts and watchers in one write
            self._progress.record(healed)
        return work

    def _save(self, target_id: str, outcome: PathOutcome) -> None:
        """A target's new version saved, then the old one superseded and the path served by the new one; or
        why none was written. In the job's own thread, one at a time."""
        self._progress.hold()
        if isinstance(outcome, PathFailure):
            self._fail(target_id, outcome.code, outcome.message)
            return
        brief, written = outcome
        path = self._progress.paths[self._targets[target_id]]
        threat = self._paths.threats[path["steps"][0]]
        record = written_record(self._run, path, threat, brief, written, self._current[target_id])
        if written.blocked:  # kept hidden, for audit only (spec v4.0 §7.4.7); the old version stays current
            self._scenarios.save(record)
            metrics.SCENARIOS.labels(ScenarioOutcome.BLOCKED).inc()
            codes = sorted({f.code for f in written.findings if f.severity == FindingSeverity.BLOCKER})
            message = ErrorMessage.REGENERATE_BLOCKED.format(codes=", ".join(codes))
            self._fail(target_id, ErrorCode.SCENARIO_BLOCKED, message)
            return
        if save_with_unique_title(self._scenarios, record, written.title_qualifier):
            metrics.SCENARIOS.labels(ScenarioOutcome.WRITTEN).inc()
        log.info(LogEvent.WRITER_SCENARIO_SAVED, path_id=path["path_id"], replaces=target_id)
        self._supersede(target_id, record["_id"])

    def _supersede(self, target_id: str, new_id: str) -> None:
        """The old version replaced, then the path served by the new one (fenced, with the run's counts)."""
        self._versions.supersede(target_id, new_id)
        self._progress.record({self._targets[target_id]: {"served": new_id}})
        self._done.add(target_id)

    def _fail(self, target_id: str, code: ErrorCode, message: str) -> None:
        log.warning(LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code)
        self._versions.note_failure(target_id, {"code": code, "message": message, "at": datetime.now(UTC)})

    def _settle_outages(self, outages: dict[str, BaseException]) -> None:
        """An outage gives the job back (raised): the retry skips every target done. On the job's last try the
        targets left keep their version, with the outage as their reason, and the run ends partial: nothing is
        left open, so failing the run would only hide its written scenarios."""
        errors = list(outages.values())
        if self._lease.attempts < Lease.MAX_ATTEMPTS or not all(isinstance(e, Unavailable) for e in errors):
            raise_most_retryable(errors)
        message = ErrorMessage.PATH_AI_UNAVAILABLE.format(tries=self._lease.attempts)
        for target_id in outages:
            self._fail(target_id, ErrorCode.UNAVAILABLE, message)
