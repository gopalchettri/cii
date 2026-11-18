"""The scenario write job: one batch of a run's paths written as one set, each saved once final."""

import dataclasses
import itertools
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.ai.chat import get_scenario_chat_model
from app.core import constants as c
from app.core import metrics
from app.core.clock import utc_now
from app.core.exceptions import TEMPORARY_ERRORS, JobFailed, LeaseLost, PathNotWritable, Unavailable, outage_reason
from app.crud.jobs import JobLease
from app.crud.scenarios import (
    ThreatScenarioRepository,
    TitleTaken,
    get_threat_scenario_repository,
    get_threat_scenario_session_repository,
)
from app.domain.intel import evidence
from app.domain.intel.switch import get_intelligence_switch
from app.domain.scenario import write
from app.domain.scenario.session import is_still_to_write
from app.domain.scenario.write import write_scenario_set
from app.domain.shared.names import name_match_key, shorten_text
from app.domain.shared.parallel import raise_most_retryable
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import Finding, FrozenContext, LiveLibrary, PathFailure, WriterBrief, WrittenScenario
from app.search.library_cache import get_library_cache
from app.worker.celery_app import send_job
from app.worker.scenario.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

PathOutcome = tuple[WriterBrief, WrittenScenario] | PathFailure
_RAISED_FROM_A_PATH: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, JobFailed, LeaseLost)


def find_evidence_outage(threat: dict[str, Any]) -> Unavailable | None:
    """Returns the outage that holds the threat's story back while its evidence search could not be made."""
    search = threat.get("intel_search")
    if search is not None and search.get("failure") is None and search.get("snapshot_id") is not None:
        return None  # searched, whatever it kept: nothing citable is written without evidence
    search = search or {}
    outage = search.get("outage")
    if outage and outage in c.AiOutage:  # the AI did not answer the search: told in the refusal's own words
        message = search.get("outage_message") or c.AI_OUTAGE_MESSAGES[c.AiOutage(outage)]
        return Unavailable(message, reason=outage)
    failure = search.get("failure") or c.EvidenceSearchFailure.NO_SNAPSHOT
    return Unavailable(c.ErrorMessage.EVIDENCE_SEARCH_UNAVAILABLE.format(reason=failure))


def write_scenario_batch(lease: JobLease) -> None:
    """Load the run and the threat library, read the switch once, then write the batch."""
    chat, threat_library = get_scenario_chat_model(), get_library_cache().get_threat_library
    run = get_threat_scenario_session_repository().get(fields="writing", _id=lease.record_id)
    if run is None:  # deleted since the claim: stopped by its owner
        raise LeaseLost(lease.record_id)
    library = threat_library()  # in memory; reloaded within a minute of an edit
    if run.get("pipeline") == c.RunPipeline.ATTACK:  # the AI writes it, MITRE ATT&CK in MongoDB confirms it
        from app.worker.scenario.attack_job import AttackBatchWriter  # it imports this module

        AttackBatchWriter(lease, run, chat, library, with_evidence=False).write()  # it searches no evidence
        return
    BatchWriter(lease, run, chat, library, get_intelligence_switch().is_on(sure=True)).write()


class BatchWriter:
    """One delivery's batch: its paths written as one set and saved one by one, then the run moved on."""

    _maps_each_card = True  # control mapping is queued as each card is saved, not only once the set is

    def __init__(
        self, lease: JobLease, run: dict[str, Any], chat: ChatModel, library: ThreatLibrary, with_evidence: bool
    ) -> None:
        """`with_evidence`: the batch's threats are searched for evidence (intelligence on); else original."""
        self._with_evidence = with_evidence
        style = c.WriterStyle.EVIDENCE_STORY if with_evidence else c.WriterStyle.ORIGINAL
        self._lease, self._run, self._scenarios = lease, run, get_threat_scenario_repository()
        self._progress = PlanProgress(lease, run)
        items = [item for item in run["job"].get("batch") or [] if item["path_id"] in self._progress.paths]
        self._batch = [item["path_id"] for item in items]
        self._replaces = {item["path_id"]: item["replaces"] for item in items if item.get("replaces")}
        kind = (run.get("last_action") or {}).get("kind")
        self._regenerate = bool(self._replaces) or kind == c.RunActionKind.REGENERATE  # or failure cards only
        self._paths = self._build_path_writer(chat, library, style)
        self._saver = PathSaver(lease, run, self._progress, self._paths.threats, self._paths.build_card)

    def _build_path_writer(self, chat: ChatModel, library: ThreatLibrary, style: c.WriterStyle) -> "PathWriter":
        return PathWriter(self._run, chat, library, style)

    def write(self) -> None:
        """Writes the batch's open paths, queues control mapping, settles any outage, moves the run on."""
        to_write = self._saver.to_write(self._batch, self._replaces, self._regenerate)
        to_write = self._drop_repeated_paths(to_write)
        held: dict[str, BaseException] = {}  # paths held back by an evidence search outage
        if self._with_evidence:
            paths, threats = self._progress.paths, self._paths.threats
            evidence.attach_evidence(self._run, threats, paths, to_write)  # one search for the paths to write
            for key in to_write:
                if (problem := find_evidence_outage(threats[paths[key]["steps"][0]])) is not None:
                    held[key] = problem
            to_write = [key for key in to_write if key not in held]
        now = utc_now()  # the action's threats time (its set picked, its evidence searched) ends here
        self._lease.update_job({}, operators={"$min": {"last_action.writing_started_at": now}})
        (self._run.get("last_action") or {}).setdefault("writing_started_at", now)  # PlanProgress reads it
        outages = held | self._write_set(to_write)
        if self._served_paths():
            send_job(c.TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        if outages:
            self._settle_outages(outages, held)
        if self._regenerate:
            self._progress.finish_regenerate(len(self._served_paths()), len(self._batch))
        else:
            self._progress.continue_or_finish()

    def _write_set(self, to_write: list[str]) -> dict[str, BaseException]:
        paths, started, numbered = self._progress.paths, utc_now(), enumerate(self._batch, start=1)
        slots = [(f"SC{place}", paths[key]) for place, key in numbered if key in to_write]  # never an id
        outages: dict[str, BaseException] = {}
        for path_id, outcome in self._paths.write_scenario_set(
            slots, self._lease.attempts >= c.Lease.MAX_ATTEMPTS, self._lease.epoch
        ):
            if isinstance(outcome, Exception):
                outages[path_id] = outcome
                continue
            self._saver.save(path_id, outcome, started)
            if self._maps_each_card and path_id in self._served_paths():
                send_job(c.TaskName.MAP_CONTROLS, self._run["_id"], self._lease.epoch)
        return outages

    def _served_paths(self) -> list[str]:
        paths = self._progress.paths
        return [key for key in self._batch if paths[key]["served"] not in (None, self._replaces.get(key))]

    def _drop_repeated_paths(self, to_write: list[str]) -> list[str]:
        first_writes = [path_id for path_id in to_write if path_id not in self._replaces]
        if not first_writes:
            return to_write
        threats, repeat = self._paths.threats, c.FindingCode.NEAR_DUPLICATE
        own = self._saver.list_held_scenarios()  # the run's own: the asset's other sessions never block one
        left = list(to_write)
        for path_id in first_writes:  # a spare may take its place (never in a regenerate)
            path = self._progress.paths[path_id]
            content = write.build_card_threat_fields(path, threats.get(path["steps"][0], {}))
            held_id = write.find_duplicate_scenario_id(content, path_id, own)
            if held_id is not None:  # the plan path keeps which scenario it repeats
                state = {"attempts": path["attempts"], "abandoned": True, "repeats": held_id}
                self._progress.abandon(path_id, state, repeat, threats)
                message = c.FindingMessage.NEAR_DUPLICATE.format(scenario_id=held_id)
                failure = {"code": repeat, "message": message}  # no outage reason any more
                card_id = write.build_scenario_id(self._run["_id"], path_id, write.FIRST_VERSION)
                changes = {"failure": failure, "updated_at": utc_now()}
                self._scenarios.update(changes, _id=card_id, status=c.ScenarioStatus.FAILED)
                left.remove(path_id)
        return left

    def _settle_outages(self, outages: dict[str, BaseException], held: dict[str, BaseException]) -> None:
        errors = list(outages.values())
        paths_own_outage = (
            self._lease.attempts >= c.Lease.MAX_ATTEMPTS
            and all(isinstance(error, Unavailable) for error in errors)
            and (self._regenerate or bool(self._served_paths()))
        )
        if not paths_own_outage:
            raise_most_retryable(errors)
        log.warning(c.LogEvent.WRITER_OUTAGE_SETTLED, paths=list(outages))  # the bound `attempt` is this try
        tries = self._lease.attempts
        for path_id, error in outages.items():  # an evidence outage keeps its own message
            outage = outage_reason(error)
            if path_id in held:
                message = str(error)
            elif outage is not None:  # which AI outage it was, in its own words
                message = c.AI_PATH_OUTAGE_MESSAGE.format(outage=str(error), tries=tries)
            else:
                message = c.ErrorMessage.PATH_AI_UNAVAILABLE.format(tries=tries)
            self._saver.save(path_id, PathFailure(c.ErrorCode.UNAVAILABLE, message, reason=outage))


class PathWriter:
    """Writes one delivery's paths with the run's frozen facts and threats, the live library and its style."""

    def __init__(self, run: dict[str, Any], chat: ChatModel, library: ThreatLibrary, style: c.WriterStyle) -> None:
        self._run_id, self._style, self._chat = run["_id"], style, chat
        self._budget = chat.max_prompt_chars // 2  # the facts' share of the model input
        self._live = LiveLibrary.from_library(library)
        self._context = FrozenContext.from_record(run["context"])
        self.threats = {threat["key"]: threat for threat in run["plan"]["threats"]}

    def build_card(
        self,
        run: dict[str, Any],
        path: dict[str, Any],
        threat: dict[str, Any],
        brief: WriterBrief,
        written: WrittenScenario,
        replaces: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """The card a written path is saved as."""
        return write.build_scenario_card(run, path, threat, brief, written, replaces)

    def write_scenario_set(
        self, slots: Sequence[tuple[str, dict[str, Any]]], last_try: bool, epoch: int = 0
    ) -> Iterator[tuple[str, PathOutcome | Exception]]:
        """Yields each path's outcome by its id as soon as it is final, written in one set of AI calls."""
        briefs: dict[str, WriterBrief] = {}
        path_ids = {label: path["path_id"] for label, path in slots}
        for label, path in slots:
            brief = self._brief(path)
            if isinstance(brief, PathFailure):
                yield path["path_id"], brief
            else:
                briefs[label] = brief
        left = dict(briefs)
        try:
            for label, written in write_scenario_set(self._chat, list(briefs.items()), epoch):
                brief = left.pop(label)
                yield path_ids[label], written if isinstance(written, PathFailure) else (brief, written)
        except Exception as error:  # a fault in one set must not cost the run its other sets
            yield from self._fail_paths_left(error, [path_ids[label] for label in left], last_try)

    def _fail_paths_left(
        self, error: Exception, left: list[str], last_try: bool
    ) -> Iterator[tuple[str, PathOutcome | Exception]]:
        failure: PathOutcome | Exception
        if isinstance(error, UnreadableAiAnswer | TruncatedAiAnswer):
            reason = shorten_text(str(error), c.Writing.PROBLEM_MAX_CHARS)
            final = last_try or isinstance(error, TruncatedAiAnswer)
            failure = PathFailure(c.ErrorCode.GENERATION_FAILED, reason) if final else Unavailable(reason)
        elif isinstance(error, _RAISED_FROM_A_PATH):
            failure = error
        else:
            log.exception(c.LogEvent.WRITER_PATH_FAILED, paths=left)
            message = c.ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            failure = PathFailure(c.ErrorCode.INTERNAL_ERROR, message)
        yield from ((path_id, failure) for path_id in left)

    def _brief(self, path: dict[str, Any]) -> WriterBrief | PathFailure:
        try:
            return write.build_writer_input(
                self.threats, path, self._context, self._budget, self._live, style=self._style
            )
        except PathNotWritable as error:
            return PathFailure(error.code, error.message)
        except Exception:  # one path's fault must not cost the run its other paths
            log.exception(c.LogEvent.WRITER_PATH_FAILED, path_id=path["path_id"])
            unexpected = c.ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            return PathFailure(c.ErrorCode.INTERNAL_ERROR, unexpected)


def save_with_unique_title(scenarios: ThreatScenarioRepository, record: dict[str, Any], qualifier: str) -> bool:
    """Saves `record` under the first title no other current scenario of the run has."""
    title = record["content"]["title"]
    qualified = (
        [f"{title} ({qualifier})"] if qualifier and name_match_key(qualifier) not in name_match_key(title) else []
    )
    titles = itertools.chain([title], qualified, (f"{title} ({number})" for number in itertools.count(2)))
    while True:
        candidate = next(titles)
        record["content"]["title"], record["title_key"] = candidate, name_match_key(candidate)
        try:
            return scenarios.save_scenario(record)
        except TitleTaken:  # the index decides: another current scenario of the run has it
            continue


def supersede_scenario_version(scenarios: ThreatScenarioRepository, old_id: str, new_id: str) -> None:
    """Marks version `old_id` replaced by `new_id` (saved first), clearing an earlier regenerate's error."""
    changes = {"superseded_by": new_id, "updated_at": utc_now(), "regenerate_error": None}
    scenarios.update(changes, _id=old_id, newest=True)


def _note_regenerate_failure(
    scenarios: ThreatScenarioRepository,
    target_id: str,
    code: c.ErrorCode,
    message: str,
    reason: c.AiOutage | None = None,
) -> None:
    log.warning(c.LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code, message=message)
    error = {"code": code, "message": message, "at": utc_now()}
    error |= {"reason": reason} if reason else {}
    changes = {"regenerate_error": error, "updated_at": error["at"]}
    scenarios.update(changes, _id=target_id, newest=True)


def _log_saved(record: dict[str, Any], saved: bool, reason: str) -> None:
    shown = {"path_id": record["path_id"], "status": record["status"], "replaces": record.get("replaces")}
    log.info(c.LogEvent.WRITER_SCENARIO_SAVED, saved=saved, blocker=reason, **shown)
    if saved and record["status"] == c.ScenarioStatus.DONE:
        metrics.SCENARIOS.labels(c.ScenarioOutcome.WRITTEN).inc()


class PathSaver:
    """Saves each outcome of one delivery, then its path's state, while the job still owns the run."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        progress: PlanProgress,
        threats: dict[str, dict[str, Any]],
        build_card: Callable[..., dict[str, Any]],
    ) -> None:
        self._lease, self._run, self._progress = lease, run, progress
        self._threats, self._scenarios = threats, get_threat_scenario_repository()
        self._build_card = build_card  # the path writer's: an attack run's cards add what MITRE ATT&CK confirmed
        self._replaced: dict[str, dict[str, Any]] = {}  # a regenerate: each path's version still to replace
        self._held: list[dict[str, Any]] | None = None  # the run's finished scenarios, once read

    def list_held_scenarios(self) -> list[dict[str, Any]]:
        """Returns the run's finished scenarios: read once, then kept up to date by this delivery's saves."""
        if self._held is None:
            self._held = self._scenarios.list_scenarios_for_duplicate_check(self._run["_id"])
        return self._held

    def to_write(self, batch: list[str], replaces: dict[str, str], regenerate: bool) -> list[str]:
        """Returns the batch's paths still to write; one written earlier is served with no AI call."""
        to_write = self._versions_to_write(replaces) if replaces else []
        paths = self._progress.paths
        first_writes = [key for key in batch if key not in replaces]
        open_paths = [key for key in first_writes if is_still_to_write(paths[key], reopen=regenerate)]
        self._progress.serve_written(open_paths)
        epoch = self._lease.epoch  # a path this job's own delivery settled is not written again
        return to_write + [
            key
            for key in open_paths
            if is_still_to_write(paths[key], reopen=regenerate) and paths[key].get("settled_epoch") != epoch
        ]

    def save(self, path_id: str, outcome: PathOutcome, started_at: datetime | None = None) -> None:
        """Saves one path's outcome, then its state on the plan (`started_at` None: no AI call)."""
        if not self._lease.renew_job():  # right before the save
            raise LeaseLost(self._run["_id"])
        path = self._progress.paths[path_id]
        if path_id in self._replaced:
            self._save_version(path, outcome, started_at)
            return
        if isinstance(outcome, PathFailure):
            record = write.build_failure_card(self._run, path, self._threats[path["steps"][0]], outcome)
            generation = {"epoch": self._lease.epoch, "started_at": started_at}
            record["generation"] = generation | {"finished_at": record["created_at"]}
            saved, reason = self._scenarios.save_scenario(record), str(outcome.code)
            _log_saved(record, saved, reason)
        else:
            record, saved, written = self._save_written(path, *outcome, started_at)
            reason = written.find_blocking_code()
        if not saved or record["status"] == c.ScenarioStatus.DONE:  # not saved: its scenario was already there
            self._progress.record({path_id: {"served": record["_id"], "abandoned": False}})
            return
        state = {"attempts": path["attempts"] + 1}
        card_outcome = c.ScenarioOutcome(record["status"])  # counted with the path's state, by the write taken
        if reason == c.ErrorCode.UNAVAILABLE and state["attempts"] < c.Generation.MAX_PATH_ATTEMPTS:
            self._progress.leave_for_next_set(path_id, state, card_outcome)
            return
        outage = outcome.reason if isinstance(outcome, PathFailure) else None  # its card's: regenerable
        changes = state | {"abandoned": True}
        self._progress.abandon(path_id, changes, outage or reason, self._threats, card_outcome)

    def _versions_to_write(self, replaces: dict[str, str]) -> list[str]:
        run_id = self._run["_id"]
        versions = self._scenarios.list(
            fields="version", session_id=run_id, path_id_in=sorted(replaces), status=c.ScenarioStatus.DONE
        )
        by_id = {row["_id"]: row for row in versions}
        to_write: list[str] = []
        healed: dict[str, dict[str, Any]] = {}
        for path_id, target_id in replaces.items():
            if (target := by_id.get(target_id)) is None:  # no longer written: skipped
                continue
            successor = target["superseded_by"] or write.build_scenario_id(run_id, path_id, target["version"] + 1)
            if not target["superseded_by"] and successor not in by_id:
                self._replaced[path_id] = target
                to_write.append(path_id)
                continue
            if not target["superseded_by"]:
                supersede_scenario_version(self._scenarios, target_id, successor)
            if self._progress.paths[path_id]["served"] != successor:
                healed[path_id] = {"served": successor}
        if healed:  # a crash before the path's fenced write: served, counts and watchers in one write
            self._progress.record(healed)
        return to_write

    def _save_version(self, path: dict[str, Any], outcome: PathOutcome, started_at: datetime | None) -> None:
        old = self._replaced[path["path_id"]]
        if isinstance(outcome, PathFailure):
            _note_regenerate_failure(self._scenarios, old["_id"], outcome.code, outcome.message, outcome.reason)
            return
        record, _, written = self._save_written(path, *outcome, started_at, old)
        if record["status"] != c.ScenarioStatus.DONE:  # kept hidden, for audit only
            message = c.ErrorMessage.REGENERATE_BLOCKED.format(codes=", ".join(written.list_blocking_codes()))
            _note_regenerate_failure(self._scenarios, old["_id"], c.ErrorCode.SCENARIO_BLOCKED, message)
            return
        supersede_scenario_version(self._scenarios, old["_id"], record["_id"])
        self._progress.record({path["path_id"]: {"served": record["_id"]}})

    def _save_written(
        self,
        path: dict[str, Any],
        brief: WriterBrief,
        written: WrittenScenario,
        started_at: datetime | None,
        replaces: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool, WrittenScenario]:
        threat = self._threats[path["steps"][0]]

        def build_record(checked: WrittenScenario) -> dict[str, Any]:
            """Builds the record of `checked`, stamped with this delivery's generation."""
            record = self._build_card(self._run, path, threat, brief, checked, replaces)
            generation = {"epoch": self._lease.epoch, "started_at": started_at}
            return record | {"generation": generation | {"finished_at": record["created_at"]}}

        record = build_record(written)
        held = self.list_held_scenarios() if not written.list_blocking_codes() else []
        duplicate_id = write.find_duplicate_scenario_id(record["content"], record["path_id"], held)
        if duplicate_id is not None:
            message = c.FindingMessage.NEAR_DUPLICATE.format(scenario_id=duplicate_id)
            duplicate_finding = Finding(c.FindingCode.NEAR_DUPLICATE, message)
            written = dataclasses.replace(written, findings=(*written.findings, duplicate_finding))
            record = build_record(written)
        saved = save_with_unique_title(self._scenarios, record, brief.threat)
        _log_saved(record, saved, written.find_blocking_code())
        if saved and record["status"] == c.ScenarioStatus.DONE and self._held is not None:
            if replaces is not None:  # a replaced version stays a finished one only while accepted
                self._held[:] = [
                    scenario
                    for scenario in self._held
                    if scenario["path_id"] != path["path_id"] or scenario.get("decision") == c.Decision.ACCEPTED
                ]
            self._held.append(record)
        return record, saved, written
