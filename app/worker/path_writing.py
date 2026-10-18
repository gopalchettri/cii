"""Writing one path's scenario in a pool thread (PathWriter) and saving it, its failure card or its new
version in the job's thread (PathSaver), a written scenario checked for a near copy first (HeldScenarios)."""

import dataclasses
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core import metrics
from app.core.constants import (
    Decision,
    ErrorCode,
    ErrorMessage,
    FindingSeverity,
    Generation,
    LogEvent,
    ScenarioOutcome,
    ScenarioStatus,
    WriterStyle,
    Writing,
)
from app.core.exceptions import TEMPORARY_ERRORS, JobFailed, LeaseLost, PathNotWritable
from app.data_access.jobs.repository import JobLease
from app.data_access.scenario.repository import TitleTaken, scenarios
from app.domain.scenario.plan import is_still_to_write
from app.domain.scenario.write import (
    build_brief,
    duplicate_of,
    failure_record,
    generation_stamp,
    scenario_id,
    title_candidates,
    write_scenario,
    written_record,
)
from app.domain.shared.names import name_match_key, shorten_text
from app.models.asset_context import FrozenContext
from app.models.library import ThreatLibrary
from app.models.scenario.write import LiveLibrary, PathFailure, WriterBrief, WrittenScenario
from app.worker.plan_progress import PlanProgress

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
        self._live = LiveLibrary.of(library)
        self._context = FrozenContext.from_record(run["context"])
        self.threats = {threat["key"]: threat for threat in run["plan"]["threats"]}

    def write(self, path: dict[str, Any], other_scenarios: tuple[str, ...] = ()) -> PathOutcome:
        """In a pool thread: build one path's brief and write its scenario (`other_scenarios`: the versions a
        regenerate must differ from). An outage or a job-wide failure is raised."""
        try:
            brief = build_brief(
                self.threats,
                path,
                self._context,
                self._budget,
                self._live,
                other_scenarios=other_scenarios,
                style=self._style,
            )
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


def save_with_unique_title(record: dict[str, Any], qualifier: str) -> bool:
    """Save `record` under the first title no other current scenario of the run has (the index decides)."""
    titles = title_candidates(record["content"]["title"], qualifier)
    while True:
        title = next(titles)
        record["content"]["title"], record["title_key"] = title, name_match_key(title)
        try:
            return scenarios.save_scenario(record)
        except TitleTaken:
            continue


def supersede_scenario_version(old_id: str, new_id: str) -> None:
    """tsg_scenarios version `old_id` replaced by `new_id` (saved first); a repeat changes nothing. An earlier
    failed regenerate's reason goes with it."""
    changes = {"superseded_by": new_id, "updated_at": datetime.now(UTC), "regenerate_error": None}
    scenarios.update(changes, _id=old_id, newest=True)


class HeldScenarios:
    """The duplicate-checked save of a written scenario, against the run's finished scenarios (kept up to date
    as the delivery saves) and the asset's held scenarios of its other runs, both read at the first check."""

    def __init__(self, run: dict[str, Any]) -> None:
        self._run = run
        self._own_run: list[dict[str, Any]] | None = None
        self._elsewhere: list[dict[str, Any]] = []

    def save(
        self, written: WrittenScenario, build: Callable[[WrittenScenario], dict[str, Any]]
    ) -> tuple[dict[str, Any], bool, WrittenScenario]:
        """Save the record `build` makes of `written` under a title of its own; a near copy first gets the
        final NEAR_DUPLICATE blocker (kept hidden). Return the record, whether it was saved, and `written`."""
        record = build(written)
        if not written.blocked:
            if self._own_run is None:
                run = self._run
                self._own_run, self._elsewhere = scenarios.list_scenarios_for_duplicate_check(
                    run["entity_id"], run["asset_id"], run["_id"]
                )
            if copy := duplicate_of(record["content"], record["path_id"], self._own_run, self._elsewhere):
                written = dataclasses.replace(written, findings=(*written.findings, copy))
                record = build(written)
        saved = save_with_unique_title(record, written.title_qualifier)
        if saved and record["status"] == ScenarioStatus.DONE and self._own_run is not None:
            self._own_run = _finished_after_save(self._own_run, record)
        return record, saved, written


def _finished_after_save(finished: list[dict[str, Any]], record: dict[str, Any]) -> list[dict[str, Any]]:
    """`finished` plus a just-saved record, less the version it replaces unless a reviewer accepted it."""
    replaced = record.get("replaces")
    kept = [item for item in finished if item["_id"] != replaced or item.get("decision") == Decision.ACCEPTED]
    return [*kept, {"_id": record["_id"], "path_id": record["path_id"], "content": record["content"]}]


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
        story: bool,
    ) -> None:
        self._lease, self._run, self._progress = lease, run, progress
        self._threats, self._story = threats, story
        self._held = HeldScenarios(run)
        self._replaced: dict[str, dict[str, Any]] = {}  # a regenerate: each path's version still to replace

    def to_write(self, batch: list[str], replaces: dict[str, str]) -> dict[str, tuple[str, ...]]:
        """The batch's paths still to write, each with the statements it must differ from; a path an earlier
        delivery wrote is served here with no AI call (`replaces`: a regenerate's targets)."""
        if replaces:
            return self._versions_to_write(replaces)
        paths, run_id = self._progress.paths, self._run["_id"]
        open_paths = [path_id for path_id in batch if is_still_to_write(paths[path_id])]
        done = ScenarioStatus.DONE
        written = scenarios.list(
            fields="path_id", session_id=run_id, path_id_in=open_paths, status=done, newest=True
        )
        if written:
            self._progress.record({row["path_id"]: {"served": row["_id"]} for row in written})
        return {path_id: () for path_id in open_paths if is_still_to_write(paths[path_id])}

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
            saved, reason, final = scenarios.save_scenario(record), str(outcome.code), outcome.final
            self._log_saved(record, saved, reason)
        else:
            record, saved, written = self._save_written(path, *outcome, started_at)
            reason, final = written.blocker, written.final  # a final rule gives the path up
        if not saved or record["status"] == ScenarioStatus.DONE:  # not saved: its scenario was already there
            self._progress.record({path_id: {"served": record["_id"]}})
            return
        # The next attempt's card replaces this one (the same id): why this one was rejected stays here.
        state = {"attempts": path["attempts"] + 1, "last_blocker": reason}
        if not (final or state["attempts"] >= Generation.MAX_PATH_ATTEMPTS):
            self._progress.record({path_id: state | {"abandoned": False}})
            return
        log.warning(LogEvent.WRITER_PATH_ABANDONED, path_id=path_id, attempts=state["attempts"])
        metrics.SCENARIOS.labels(ScenarioOutcome.ABANDONED).inc()
        self._progress.abandon(path_id, state | {"abandoned": True}, reason, self._threats, self._story)

    def _versions_to_write(self, replaces: dict[str, str]) -> dict[str, tuple[str, ...]]:
        """A regenerate's paths still to write, each with its versions' statements (oldest first). A next
        version an earlier delivery saved is finished here; a target no longer written is skipped."""
        run_id = self._run["_id"]
        versions = scenarios.list(
            fields="version",
            sort="version",
            session_id=run_id,
            path_id_in=sorted(replaces),
            status=ScenarioStatus.DONE,
        )
        by_id = {row["_id"]: row for row in versions}
        statements: defaultdict[str, list[str]] = defaultdict(list)
        for row in versions:
            statements[row["path_id"]].append(row["content"]["statement"])
        to_write: dict[str, tuple[str, ...]] = {}
        healed: dict[str, dict[str, Any]] = {}
        for path_id, target_id in replaces.items():
            if (target := by_id.get(target_id)) is None:
                continue
            successor = target["superseded_by"] or scenario_id(run_id, path_id, target["version"] + 1)
            if not target["superseded_by"] and successor not in by_id:
                self._replaced[path_id], to_write[path_id] = target, tuple(statements[path_id])
                continue
            if not target["superseded_by"]:
                supersede_scenario_version(target_id, successor)
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
            self._note_failure(old["_id"], outcome.code, outcome.message)
            return
        record, _, written = self._save_written(path, *outcome, started_at, old)
        if record["status"] != ScenarioStatus.DONE:  # kept hidden, for audit only
            codes = sorted({f.code for f in written.findings if f.severity == FindingSeverity.BLOCKER})
            message = ErrorMessage.REGENERATE_BLOCKED.format(codes=", ".join(codes))
            self._note_failure(old["_id"], ErrorCode.SCENARIO_BLOCKED, message)
            return
        supersede_scenario_version(old["_id"], record["_id"])
        self._progress.record({path["path_id"]: {"served": record["_id"]}})

    def _save_written(
        self,
        path: dict[str, Any],
        brief: WriterBrief,
        written: WrittenScenario,
        started_at: datetime | None,
        replaces: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool, WrittenScenario]:
        """Build a written scenario's record, check it for a near copy, save and log it."""
        threat = self._threats[path["steps"][0]]

        def build(checked: WrittenScenario) -> dict[str, Any]:
            """The record of `checked`, stamped with this delivery's generation."""
            record = written_record(self._run, path, threat, brief, checked, replaces)
            record["generation"] = generation_stamp(self._lease.epoch, started_at, record)
            return record

        record, saved, written = self._held.save(written, build)
        self._log_saved(record, saved, written.blocker)
        return record, saved, written

    def _log_saved(self, record: dict[str, Any], saved: bool, reason: str) -> None:
        """Log one saved record and count it."""
        shown = {"path_id": record["path_id"], "status": record["status"], "replaces": record.get("replaces")}
        log.info(LogEvent.WRITER_SCENARIO_SAVED, saved=saved, blocker=reason, **shown)
        if saved:
            metrics.SCENARIOS.labels(_OUTCOMES[record["status"]]).inc()

    def _note_failure(self, target_id: str, code: ErrorCode, message: str) -> None:
        """Log why a regenerate wrote no new version and note it on the old one."""
        log.warning(LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code, reason=message)
        error = {"code": code, "message": message, "at": datetime.now(UTC)}
        scenarios.update({"regenerate_error": error, "updated_at": error["at"]}, _id=target_id, newest=True)
