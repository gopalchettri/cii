"""Writing one path's scenario in a pool thread (PathWriter) and saving it, its failure card or its new
version in the job's thread (PathSaver), a written scenario checked for a near copy right before its save."""

import dataclasses
import threading
from datetime import datetime
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core import metrics
from app.core.clock import utc_now
from app.core.constants import (
    AiOutage,
    ErrorCode,
    ErrorMessage,
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
from app.domain.scenario.plan import is_still_to_write
from app.domain.scenario.write import (
    blocking_codes,
    blocking_finding_code,
    build_brief,
    duplicate_of,
    failure_record,
    generation_stamp,
    is_final,
    live_library_of,
    path_style,
    scenario_id,
    split_threat_actions,
    title_candidates,
    write_scenario,
    written_record,
)
from app.domain.shared.names import name_match_key, shorten_text
from app.models.library.library import ThreatLibrary
from app.models.scenario.asset_context import FrozenContext
from app.models.scenario.write import Finding, PathFailure, WriterBrief, WrittenScenario
from app.worker.scenario.plan_progress import PlanProgress

log = structlog.get_logger(__name__)

#: What writing one path gave: its brief and scenario, or why there is none.
PathOutcome = tuple[WriterBrief, WrittenScenario] | PathFailure
#: What one path's work raises instead of returning a card: the job retries, fails or (lease lost) stops.
_RAISED_FROM_A_PATH: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, JobFailed, LeaseLost)
#: tsg_scenarios_total's outcome for each saved status.
_OUTCOMES = {
    ScenarioStatus.DONE: ScenarioOutcome.WRITTEN,
    ScenarioStatus.BLOCKED: ScenarioOutcome.BLOCKED,
    ScenarioStatus.FAILED: ScenarioOutcome.FAILED,
}


class PathWriter:
    """What every path of one delivery is written with: the run's frozen facts and threats, the library as it
    is now, the writer and the delivery's style."""

    def __init__(
        self, run: dict[str, Any], chat: ChatModel, library: ThreatLibrary, style: WriterStyle
    ) -> None:
        self._run_id, self._style, self._chat = run["_id"], style, chat
        self._budget = chat.max_prompt_chars // 2  # the facts' share of the model input
        self._live = live_library_of(library)
        self._context = FrozenContext.from_record(run["context"])
        self.threats = {threat["key"]: threat for threat in run["plan"]["threats"]}
        self._actions: dict[str, tuple[str, ...] | Unavailable] = {}  # each threat's split (or its outage)
        self._split_locks: dict[str, threading.Lock] = {}  # one per threat

    def write(self, path: dict[str, Any]) -> PathOutcome:
        """In a pool thread: build one path's brief in its own style, with its threat's actions, and write its
        scenario. An outage or a job-wide failure is raised."""
        try:
            style = path_style(self.threats, path, self._style)
            brief = build_brief(self.threats, path, self._context, self._budget, self._live, style=style)
            brief = dataclasses.replace(brief, threat_actions=self._threat_actions(brief.threat))
            return brief, write_scenario(self._chat, brief)
        except PathNotWritable as exc:
            return PathFailure(exc.code, exc.message, final=True)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            return PathFailure(ErrorCode.GENERATION_FAILED, shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS))
        except _RAISED_FROM_A_PATH:
            raise
        except Exception:  # one path's fault must not cost the run its other paths
            log.exception(LogEvent.WRITER_PATH_FAILED, path_id=path["path_id"])
            unexpected = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            return PathFailure(ErrorCode.INTERNAL_ERROR, unexpected)

    def _threat_actions(self, threat: str) -> tuple[str, ...]:
        """The actions `threat`'s name states, split once per delivery; its other paths wait for it, and an
        outage is raised to each with no second ask."""
        with self._split_locks.setdefault(threat, threading.Lock()):  # dict.setdefault is atomic
            if threat not in self._actions:
                try:
                    self._actions[threat] = split_threat_actions(self._chat, threat)
                except Unavailable as exc:
                    self._actions[threat] = exc
            found = self._actions[threat]
        if isinstance(found, Unavailable):
            raise found
        return found


def save_with_unique_title(
    scenarios: ThreatScenarioRepository, record: dict[str, Any], qualifier: str
) -> bool:
    """Save `record` under the first title no other current scenario of the run has (the index decides)."""
    titles = title_candidates(record["content"]["title"], qualifier)
    while True:
        title = next(titles)
        record["content"]["title"], record["title_key"] = title, name_match_key(title)
        try:
            return scenarios.save_scenario(record)
        except TitleTaken:
            continue


def supersede_scenario_version(scenarios: ThreatScenarioRepository, old_id: str, new_id: str) -> None:
    """tsg_scenarios version `old_id` replaced by `new_id` (saved first); a repeat changes nothing. An earlier
    failed regenerate's reason goes with it."""
    changes = {"superseded_by": new_id, "updated_at": utc_now(), "regenerate_error": None}
    scenarios.update(changes, _id=old_id, newest=True)


def _near_copy_held_now(
    scenarios: ThreatScenarioRepository, run: dict[str, Any], record: dict[str, Any]
) -> Finding | None:
    """The final NEAR_DUPLICATE finding when `record` copies one of the run's finished scenarios held now
    (the asset's other sessions never block one: D15)."""
    own = scenarios.list_scenarios_for_duplicate_check(run["_id"])
    return duplicate_of(record["content"], record["path_id"], own)


def _served_by(scenario: str) -> dict[str, Any]:
    """A path's state once `scenario` serves it: a written path is never given up."""
    return {"served": scenario, "abandoned": False}


def _log_saved(record: dict[str, Any], saved: bool, reason: str) -> None:
    """Log one saved record and count it."""
    shown = {"path_id": record["path_id"], "status": record["status"], "replaces": record.get("replaces")}
    log.info(LogEvent.WRITER_SCENARIO_SAVED, saved=saved, blocker=reason, **shown)
    if saved:
        metrics.SCENARIOS.labels(_OUTCOMES[record["status"]]).inc()


class PathSaver:
    """Each outcome of one delivery saved in the job's thread once the job still owns the run: a first write's
    scenario or card, then its path's state. A regenerate keeps version n current until n+1 is saved (a crash
    leaves both current, never neither); a blocked n+1 stays hidden and n keeps why."""

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

    def to_write(self, batch: list[str], replaces: dict[str, str], regenerate: bool) -> list[str]:
        """The batch's paths still to write; a path an earlier delivery wrote is served here with no AI call
        (`replaces`: a regenerate's versions to replace, each written afresh; its other paths are outage
        cards' paths, written again even once given up)."""
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
            self._progress.record({row["path_id"]: _served_by(row["_id"]) for row in written})
        return to_write + [key for key in open_paths if is_still_to_write(paths[key], reopen=regenerate)]

    def save(self, path_id: str, outcome: PathOutcome, started_at: datetime | None = None) -> None:
        """Save one path's outcome, then its state on the plan. `started_at`: when its AI work began (None:
        decided with no AI call)."""
        self._progress.hold()
        path = self._progress.paths[path_id]
        if path_id in self._replaced:
            self._save_version(path, outcome, started_at)
            return
        if isinstance(outcome, PathFailure):
            steps = path.get("steps") or []
            threat = self._threats.get(steps[0]) if len(steps) == 1 else None
            record = failure_record(self._run, path, threat, outcome)
            record["generation"] = generation_stamp(self._lease.epoch, started_at, record)
            saved, reason, final = self._scenarios.save_scenario(record), str(outcome.code), outcome.final
            _log_saved(record, saved, reason)
        else:
            record, saved, written = self._save_written(path, *outcome, started_at)
            reason, final = blocking_finding_code(written), is_final(written)  # noqa: F841 - retry below
        if not saved or record["status"] == ScenarioStatus.DONE:  # not saved: its scenario was already there
            self._progress.record({path_id: _served_by(record["_id"])})
            return
        # The next attempt's card replaces this one (the same id): why this one was rejected stays here.
        state = {"attempts": path["attempts"] + 1, "last_blocker": reason}
        if reason == ErrorCode.UNAVAILABLE and state["attempts"] < Generation.MAX_PATH_ATTEMPTS:
            self._progress.leave_for_next_set(path_id, state)  # an outage passes: a later set writes it
            return
        # The writer's own retry is off; uncomment to retry a blocked path later, up to MAX_PATH_ATTEMPTS.
        # if not (final or state["attempts"] >= Generation.MAX_PATH_ATTEMPTS):
        #     self._progress.record({path_id: state | {"abandoned": False}})
        #     return
        self._progress.abandon(path_id, state | {"abandoned": True}, reason, self._threats)

    def _versions_to_write(self, replaces: dict[str, str]) -> list[str]:
        """A regenerate's paths still to write. A next version an earlier delivery saved is finished here; a
        target no longer written is skipped."""
        run_id = self._run["_id"]
        versions = self._scenarios.list(
            fields="version", session_id=run_id, path_id_in=sorted(replaces), status=ScenarioStatus.DONE
        )
        by_id = {row["_id"]: row for row in versions}
        to_write: list[str] = []
        healed: dict[str, dict[str, Any]] = {}
        for path_id, target_id in replaces.items():
            if (target := by_id.get(target_id)) is None:
                continue
            successor = target["superseded_by"] or scenario_id(run_id, path_id, target["version"] + 1)
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
        """Save a new version, then supersede the old one and serve the path with it; else note on the old
        one, which stays current, why none was written."""
        old = self._replaced[path["path_id"]]
        if isinstance(outcome, PathFailure):
            self._note_failure(old["_id"], outcome.code, outcome.message, outcome.reason)
            return
        record, _, written = self._save_written(path, *outcome, started_at, old)
        if record["status"] != ScenarioStatus.DONE:  # kept hidden, for audit only
            message = ErrorMessage.REGENERATE_BLOCKED.format(codes=", ".join(blocking_codes(written)))
            self._note_failure(old["_id"], ErrorCode.SCENARIO_BLOCKED, message)
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
        """Build a written scenario's record, check it for a near copy held now, save and log it."""
        threat = self._threats[path["steps"][0]]

        def build(checked: WrittenScenario) -> dict[str, Any]:
            """The record of `checked`, stamped with this delivery's generation."""
            record = written_record(self._run, path, threat, brief, checked, replaces)
            record["generation"] = generation_stamp(self._lease.epoch, started_at, record)
            return record

        record = build(written)
        if not blocking_codes(written) and (copy := _near_copy_held_now(self._scenarios, self._run, record)):
            written = dataclasses.replace(written, findings=(*written.findings, copy))
            record = build(written)
        saved = save_with_unique_title(self._scenarios, record, written.title_qualifier)
        _log_saved(record, saved, blocking_finding_code(written))
        return record, saved, written

    def _note_failure(
        self, target_id: str, code: ErrorCode, message: str, reason: AiOutage | None = None
    ) -> None:
        """Log why a regenerate wrote no new version and note it on the old one, with the AI outage if one."""
        log.warning(LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code, reason=message)
        error = {"code": code, "message": message, "at": utc_now()}
        error |= {"reason": reason} if reason else {}
        changes = {"regenerate_error": error, "updated_at": error["at"]}
        self._scenarios.update(changes, _id=target_id, newest=True)
