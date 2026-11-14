"""Writing a set of paths' scenarios (PathWriter) and saving each card or new version (PathSaver)."""

import dataclasses
import itertools
from collections.abc import Iterator, Sequence
from datetime import datetime
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    AiOutage,
    Decision,
    ErrorCode,
    ErrorMessage,
    FindingCode,
    FindingMessage,
    Generation,
    LogEvent,
    ScenarioOutcome,
    ScenarioStatus,
    WriterStyle,
    Writing,
)
from app.core.exceptions import TEMPORARY_ERRORS, JobFailed, LeaseLost, PathNotWritable, Unavailable
from app.data_access.jobs.job_repository import JobLease
from app.data_access.scenario.threat_scenario_repository import ThreatScenarioRepository, TitleTaken
from app.domain.scenario.session import is_still_to_write
from app.domain.scenario.write import (
    build_failure_card,
    build_scenario_card,
    build_scenario_id,
    build_writer_input,
    find_duplicate_scenario_id,
    write_scenario_set,
)
from app.domain.shared.names import name_match_key, shorten_text
from app.models.library.library import ThreatLibrary
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.write import Finding, LiveLibrary, PathFailure, WriterBrief, WrittenScenario
from app.worker.scenario.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: What writing one path gave: its brief and scenario, or why there is none.
PathOutcome = tuple[WriterBrief, WrittenScenario] | PathFailure
#: What a set's AI work raises instead of giving cards: its paths left retry, fail or (lease lost) stop.
_RAISED_FROM_A_PATH: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, JobFailed, LeaseLost)


class PathWriter:
    """Writes one delivery's paths with the run's frozen facts and threats, the live library and its style."""

    def __init__(
        self, run: dict[str, Any], chat: ChatModel, library: ThreatLibrary, style: WriterStyle
    ) -> None:
        self._run_id, self._style, self._chat = run["_id"], style, chat
        self._budget = chat.max_prompt_chars // 2  # the facts' share of the model input
        self._live = LiveLibrary.from_library(library)
        self._context = FrozenContext.from_record(run["context"])
        self.threats = {threat["key"]: threat for threat in run["plan"]["threats"]}

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
        except (UnreadableAiAnswer, TruncatedAiAnswer) as error:
            # an outage to retry, but failure cards on the last try; one cut off would be cut off again
            reason = shorten_text(str(error), Writing.PROBLEM_MAX_CHARS)
            final = last_try or isinstance(error, TruncatedAiAnswer)
            failure = PathFailure(ErrorCode.GENERATION_FAILED, reason) if final else Unavailable(reason)
            yield from ((path_ids[label], failure) for label in left)
        except _RAISED_FROM_A_PATH as error:
            yield from ((path_ids[label], error) for label in left)
        except Exception:  # a fault in one set must not cost the run its other sets
            log.exception(LogEvent.WRITER_PATH_FAILED, paths=[path_ids[label] for label in left])
            message = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            yield from ((path_ids[label], PathFailure(ErrorCode.INTERNAL_ERROR, message)) for label in left)

    def _brief(self, path: dict[str, Any]) -> WriterBrief | PathFailure:
        """Builds a path's brief; a path the plan cannot support fails for good, with no AI call."""
        try:
            return build_writer_input(
                self.threats, path, self._context, self._budget, self._live, style=self._style
            )
        except PathNotWritable as error:
            return PathFailure(error.code, error.message, final=True)
        except Exception:  # one path's fault must not cost the run its other paths
            log.exception(LogEvent.WRITER_PATH_FAILED, path_id=path["path_id"])
            unexpected = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            return PathFailure(ErrorCode.INTERNAL_ERROR, unexpected)


def save_with_unique_title(
    scenarios: ThreatScenarioRepository, record: dict[str, Any], qualifier: str
) -> bool:
    """Saves `record` under the first title no other current scenario of the run has."""
    title = record["content"]["title"]
    qualified = (
        [f"{title} ({qualifier})"]
        if qualifier and name_match_key(qualifier) not in name_match_key(title)
        else []
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
    code: ErrorCode,
    message: str,
    reason: AiOutage | None = None,
) -> None:
    """Logs why a regenerate wrote no new version and notes it on the old one."""
    log.warning(LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code, message=message)
    error = {"code": code, "message": message, "at": utc_now()}
    error |= {"reason": reason} if reason else {}
    changes = {"regenerate_error": error, "updated_at": error["at"]}
    scenarios.update(changes, _id=target_id, newest=True)


def _build_served_state(scenario: str) -> dict[str, Any]:
    """Returns a path's state once `scenario` serves it: a written path is never given up."""
    return {"served": scenario, "abandoned": False}


def _log_saved(record: dict[str, Any], saved: bool, reason: str) -> None:
    """Logs one saved record and counts a written one."""
    shown = {"path_id": record["path_id"], "status": record["status"], "replaces": record.get("replaces")}
    log.info(LogEvent.WRITER_SCENARIO_SAVED, saved=saved, blocker=reason, **shown)
    if saved and record["status"] == ScenarioStatus.DONE:
        metrics.SCENARIOS.labels(ScenarioOutcome.WRITTEN).inc()


def _add_saved_scenario_to_held(held: list[dict[str, Any]], record: dict[str, Any]) -> None:
    """Adds a saved finished scenario to `held`; a new version drops its path's unaccepted ones."""
    if record["replaces"] is not None:  # a replaced version stays a finished one only while accepted
        held[:] = [
            scenario
            for scenario in held
            if scenario["path_id"] != record["path_id"] or scenario.get("decision") == Decision.ACCEPTED
        ]
    held.append(record)


class PathSaver:
    """Saves each outcome of one delivery, then its path's state, while the job still owns the run."""

    def __init__(
        self,
        lease: JobLease,
        run: dict[str, Any],
        progress: PlanProgress,
        threats: dict[str, dict[str, Any]],
        scenarios: ThreatScenarioRepository,
    ) -> None:
        self._lease, self._run, self._progress = lease, run, progress
        self._threats, self._scenarios = threats, scenarios
        self._replaced: dict[str, dict[str, Any]] = {}  # a regenerate: each path's version still to replace
        self._held: list[dict[str, Any]] | None = None  # the run's finished scenarios, once read

    def list_held_scenarios(self) -> list[dict[str, Any]]:
        """Returns the run's finished scenarios: read once, then kept up to date by this delivery's saves."""
        # Only the lease holder saves the run's scenarios, and no review decision is taken while the run is
        # queued or running (check_session_ready_for_review): the list read once stays true for the delivery.
        if self._held is None:
            self._held = self._scenarios.list_scenarios_for_duplicate_check(self._run["_id"])
        return self._held

    def to_write(self, batch: list[str], replaces: dict[str, str], regenerate: bool) -> list[str]:
        """Returns the batch's paths still to write; one written earlier is served with no AI call."""
        to_write = self._versions_to_write(replaces) if replaces else []
        paths, run_id = self._progress.paths, self._run["_id"]
        first_writes = [key for key in batch if key not in replaces]
        open_paths = [key for key in first_writes if is_still_to_write(paths[key], reopen=regenerate)]
        if not open_paths:
            return to_write
        done = ScenarioStatus.DONE
        written = self._scenarios.list(
            fields="path_id", session_id=run_id, path_id_in=open_paths, status=done, newest=True
        )
        if written:
            self._progress.record({row["path_id"]: _build_served_state(row["_id"]) for row in written})
        settled = self._progress.settled_by_this_job
        return to_write + [
            key for key in open_paths if is_still_to_write(paths[key], reopen=regenerate) and not settled(key)
        ]

    def save(self, path_id: str, outcome: PathOutcome, started_at: datetime | None = None) -> None:
        """Saves one path's outcome, then its state on the plan (`started_at` None: no AI call)."""
        self._progress.hold()
        path = self._progress.paths[path_id]
        if path_id in self._replaced:
            self._save_version(path, outcome, started_at)
            return
        if isinstance(outcome, PathFailure):
            steps = path.get("steps") or []
            threat = self._threats.get(steps[0]) if len(steps) == 1 else None
            record = build_failure_card(self._run, path, threat, outcome)
            generation = {"epoch": self._lease.epoch, "started_at": started_at}
            record["generation"] = generation | {"finished_at": record["created_at"]}
            saved, reason = self._scenarios.save_scenario(record), str(outcome.code)
            _log_saved(record, saved, reason)
        else:
            record, saved, written = self._save_written(path, *outcome, started_at)
            reason = written.find_blocking_code()
        if not saved or record["status"] == ScenarioStatus.DONE:  # not saved: its scenario was already there
            self._progress.record({path_id: _build_served_state(record["_id"])})
            return
        # Why this card was rejected stays on the path; only an outage's later set writes it again (same id).
        state = {"attempts": path["attempts"] + 1, "last_blocker": reason}
        card_outcome = ScenarioOutcome(record["status"])  # counted with the path's state, by the write taken
        if reason == ErrorCode.UNAVAILABLE and state["attempts"] < Generation.MAX_PATH_ATTEMPTS:
            # an outage passes: a later set writes it
            self._progress.leave_for_next_set(path_id, state, card_outcome)
            return
        # any other card, or the last outage, gives the path up at once: one blocked draft is never retried
        outage = outcome.reason if isinstance(outcome, PathFailure) else None  # its card's: regenerable
        changes = state | {"abandoned": True}
        self._progress.abandon(path_id, changes, outage or reason, self._threats, card_outcome)

    def _versions_to_write(self, replaces: dict[str, str]) -> list[str]:
        """Returns a regenerate's paths still to write, finishing a next version an earlier delivery saved."""
        run_id = self._run["_id"]
        versions = self._scenarios.list(
            fields="version", session_id=run_id, path_id_in=sorted(replaces), status=ScenarioStatus.DONE
        )
        by_id = {row["_id"]: row for row in versions}
        to_write: list[str] = []
        healed: dict[str, dict[str, Any]] = {}
        for path_id, target_id in replaces.items():
            if (target := by_id.get(target_id)) is None:  # no longer written: skipped
                continue
            successor = target["superseded_by"] or build_scenario_id(run_id, path_id, target["version"] + 1)
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
        """Saves a new version and serves the path with it; else notes on the current one why none was."""
        old = self._replaced[path["path_id"]]
        if isinstance(outcome, PathFailure):
            _note_regenerate_failure(
                self._scenarios, old["_id"], outcome.code, outcome.message, outcome.reason
            )
            return
        record, _, written = self._save_written(path, *outcome, started_at, old)
        if record["status"] != ScenarioStatus.DONE:  # kept hidden, for audit only
            message = ErrorMessage.REGENERATE_BLOCKED.format(codes=", ".join(written.list_blocking_codes()))
            _note_regenerate_failure(self._scenarios, old["_id"], ErrorCode.SCENARIO_BLOCKED, message)
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
        """Builds a written scenario's record, checks it for a near copy held now, saves and logs it."""
        threat = self._threats[path["steps"][0]]

        def build_record(checked: WrittenScenario) -> dict[str, Any]:
            """Builds the record of `checked`, stamped with this delivery's generation."""
            record = build_scenario_card(self._run, path, threat, brief, checked, replaces)
            generation = {"epoch": self._lease.epoch, "started_at": started_at}
            return record | {"generation": generation | {"finished_at": record["created_at"]}}

        record = build_record(written)
        held = self.list_held_scenarios() if not written.list_blocking_codes() else []
        duplicate_id = find_duplicate_scenario_id(record["content"], record["path_id"], held)
        if duplicate_id is not None:
            message = FindingMessage.NEAR_DUPLICATE.format(scenario_id=duplicate_id)
            duplicate_finding = Finding(FindingCode.NEAR_DUPLICATE, message)
            written = dataclasses.replace(written, findings=(*written.findings, duplicate_finding))
            record = build_record(written)
        saved = save_with_unique_title(self._scenarios, record, brief.threat)
        _log_saved(record, saved, written.find_blocking_code())
        if replaces is not None and not saved:  # another version took its id meanwhile: read them again
            self._held = None
        elif saved and record["status"] == ScenarioStatus.DONE and self._held is not None:
            _add_saved_scenario_to_held(self._held, record)
        return record, saved, written
