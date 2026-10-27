"""The scenario write job: one batch of a run's paths written at once, each saved as soon as it is done, then
the set's next batch handed over, the set ended, or the regenerate ended."""

import contextvars
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import partial
from typing import Any

import structlog

from app.ai import ChatModel
from app.ai.common import outage_reason
from app.core.clock import utc_now
from app.core.constants import (
    AI_PATH_OUTAGE_MESSAGE,
    ErrorCode,
    ErrorMessage,
    FindingCode,
    FindingMessage,
    Generation,
    Lease,
    LogEvent,
    RunActionKind,
    ScenarioStatus,
    TaskName,
    WriterStyle,
)
from app.core.exceptions import LeaseLost, Unavailable
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.data_access.jobs.job_repository import JobLease
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository
from app.data_access.scenario.threat_scenario_session_repository import ThreatScenarioSessionRepository
from app.domain.external_intelligence.evidence_finder import EvidenceFinder
from app.domain.scenario.write import evidence_problem, held_repeat_of, scenario_id
from app.domain.shared.parallel import raise_most_retryable
from app.models.library.library import ThreatLibrary
from app.models.scenario.write import PathFailure
from app.worker.celery_app import send_job
from app.worker.external_intelligence.evidence_at_write import EvidenceAtWrite
from app.worker.scenario.path_writing import PathOutcome, PathSaver, PathWriter
from app.worker.scenario.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: Builds one batch's evidence search from its run, its threats and its progress.
EvidenceSearchBuilder = Callable[[dict[str, Any], dict[str, dict[str, Any]], PlanProgress], EvidenceAtWrite]


class ScenarioWriteJob:
    """Writes scenario batches; long-lived, one per worker."""

    def __init__(
        self,
        *,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        chat: ChatModel,
        threat_library: Callable[[], ThreatLibrary],
        switch: IntelligenceSwitch,
        evidence_finder: Callable[[], EvidenceFinder],
        feeds: IntelFeedRepository,
        audit: AuditRepository,
    ) -> None:
        """`evidence_finder` is asked for only while intelligence is on, so with it off nothing is built."""
        self._sessions, self._scenarios, self._chat = sessions, scenarios, chat
        self._threat_library, self._switch = threat_library, switch
        self._evidence_finder, self._feeds, self._audit = evidence_finder, feeds, audit

    def write_scenario_batch(self, lease: JobLease) -> None:
        """Load the run and the threat library, read the switch once, then write the batch."""
        run = self._sessions.get(fields="writing", _id=lease.record_id)
        if run is None:  # deleted since the claim: stopped by its owner
            raise LeaseLost(lease.record_id)
        for threat in run["plan"]["threats"]:  # the evidence an older plan kept: each write searches its own
            threat.pop("evidence", None)
            threat.pop("intel_search", None)
        library = self._threat_library()  # in memory; reloaded within a minute of an edit
        # A switch in doubt raises Unavailable, so the job is retried: no story without its evidence.
        evidence = self._evidence_at_write if self._switch.is_on(sure=True) else None
        BatchWriter(lease, run, self._chat, library, self._sessions, self._scenarios, evidence).write()

    def _evidence_at_write(
        self, run: dict[str, Any], threats: dict[str, dict[str, Any]], progress: PlanProgress
    ) -> EvidenceAtWrite:
        """The evidence search of one batch."""
        return EvidenceAtWrite(run, threats, progress, self._evidence_finder(), self._feeds, self._audit)


class BatchWriter:
    """One delivery's batch: its paths written at once and saved one by one, then the run moved on."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        chat: ChatModel,
        library: ThreatLibrary,
        sessions: ThreatScenarioSessionRepository,
        scenarios: ThreatScenarioRepository,
        evidence: EvidenceSearchBuilder | None,
    ) -> None:
        """`evidence`: the batch's evidence search while intelligence is on (evidence stories, a path with
        nothing citable written without evidence); None writes the original scenarios."""
        style = WriterStyle.ORIGINAL if evidence is None else WriterStyle.EVIDENCE_STORY
        self._lease, self._run, self._scenarios = lease, run, scenarios
        self._progress = PlanProgress(lease, run, sessions, scenarios)
        self._paths = PathWriter(run, chat, library, style)
        self._saver = PathSaver(lease, run, self._progress, self._paths.threats, scenarios)
        self._evidence = None if evidence is None else evidence(run, self._paths.threats, self._progress)
        items = [item for item in run["job"].get("batch") or [] if item["path_id"] in self._progress.paths]
        self._batch = [item["path_id"] for item in items]
        self._replaces = {item["path_id"]: item["replaces"] for item in items if item.get("replaces")}
        kind = (run.get("last_action") or {}).get("kind")
        self._regenerate = bool(self._replaces) or kind == RunActionKind.REGENERATE  # or failure cards only
        self._evidence_waits: set[str] = set()  # paths held back by an evidence search outage

    def write(self) -> None:
        """Write the batch's open paths (control mapping queued as each scenario is saved), queue it again for
        the whole batch, settle any outage, then move the run on."""
        to_write = self._saver.to_write(self._batch, self._replaces, self._regenerate)
        to_write = self._without_repeats(to_write)
        outages: dict[str, BaseException] = {}
        if self._evidence is not None:
            self._evidence.attach(to_write)  # one evidence search for the paths about to be written
            to_write = [key for key in to_write if not self._held_back(key, outages)]
        paths = self._progress.paths
        path_jobs = {key: partial(self._paths.write, paths[key]) for key in to_write}
        outages |= write_at_once(path_jobs, self._save)
        # Sent for every scenario of the batch, whichever delivery saved it, before an outage can raise: a
        # delivery that died or failed after saving must not leave its controls to the sweep. The controls
        # job claims each scenario once.
        if self._served_paths():
            send_job(TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        if outages:
            self._settle_outages(outages)
        if self._regenerate:
            self._progress.finish_regenerate(len(self._served_paths()), len(self._batch))
        else:
            self._progress.continue_or_finish()

    def _save(self, path_id: str, outcome: PathOutcome, started_at: datetime) -> None:
        """Save one path's outcome; a scenario that now serves it has its controls mapped while the batch's
        other paths are still being written (a message that finds the run being mapped costs one update)."""
        self._saver.save(path_id, outcome, started_at)
        if path_id in self._served_paths():
            send_job(TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)

    def _served_paths(self) -> list[str]:
        """The batch's paths served by a scenario written for it (a regenerate's: a new version, or an
        outage card's path written at last)."""
        paths = self._progress.paths
        return [key for key in self._batch if paths[key]["served"] not in (None, self._replaces.get(key))]

    def _without_repeats(self, to_write: list[str]) -> list[str]:
        """Give up, with no AI call and no new card, each path to write for the first time repeating a
        scenario the run's other paths hold now (the asset's other sessions never block one: D15); a spare may
        take its place (never in a regenerate). The paths left to write."""
        first_writes = [path_id for path_id in to_write if path_id not in self._replaces]
        if not first_writes:
            return to_write
        threats, repeat = self._paths.threats, FindingCode.NEAR_DUPLICATE
        own = self._scenarios.list_scenarios_for_duplicate_check(self._run["_id"])
        left = list(to_write)
        for path_id in first_writes:
            path = self._progress.paths[path_id]
            steps = path.get("steps") or []
            held_id = held_repeat_of(path, threats.get(steps[0], {}) if steps else {}, own)
            if held_id is not None:  # the plan path keeps which scenario it repeats
                state = {
                    "attempts": path["attempts"],
                    "last_blocker": repeat,
                    "abandoned": True,
                    "repeats": held_id,
                }
                self._progress.abandon(path_id, state, repeat, threats)
                self._card_says_it_repeats(path_id, held_id)
                left.remove(path_id)
        return left

    def _card_says_it_repeats(self, path_id: str, held_id: str) -> None:
        """An outage's failure card on a path given up as a repeat says so instead: it is not regenerated."""
        message = FindingMessage.NEAR_DUPLICATE.format(scenario_id=held_id)
        failure = {"code": FindingCode.NEAR_DUPLICATE, "message": message}  # no outage reason any more
        card_id = scenario_id(self._run["_id"], path_id, 1)
        changes = {"failure": failure, "updated_at": utc_now()}
        self._scenarios.update(changes, _id=card_id, status=ScenarioStatus.FAILED)

    def _held_back(self, path_id: str, outages: dict[str, BaseException]) -> bool:
        """Hold a story back while its threat's evidence search could not be made: it waits as an outage."""
        steps = self._progress.paths[path_id].get("steps") or []
        problem = evidence_problem(self._paths.threats[steps[0]]) if steps else None
        if problem is not None:
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
            and (self._regenerate or bool(self._served_paths()))
        )
        if not paths_own_outage:
            raise_most_retryable(errors)
        log.warning(LogEvent.WRITER_OUTAGE_SETTLED, paths=list(outages), attempts=self._lease.attempts)
        tries = self._lease.attempts
        for path_id, error in outages.items():  # an evidence outage keeps its own message
            outage = outage_reason(error)
            if path_id in self._evidence_waits:
                message = str(error)
            elif outage is not None:  # which AI outage it was, in its own words
                message = AI_PATH_OUTAGE_MESSAGE.format(outage=str(error), tries=tries)
            else:
                message = ErrorMessage.PATH_AI_UNAVAILABLE.format(tries=tries)
            self._saver.save(path_id, PathFailure(ErrorCode.UNAVAILABLE, message, reason=outage))


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
    started = utc_now()
    return started, job()
