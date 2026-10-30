"""Writing a set of paths' scenarios (PathWriter) and saving each, its failure card or its new version as
soon as it is final (PathSaver), a written scenario checked for a near copy right before its save."""

import dataclasses
from collections.abc import Iterator, Sequence
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
    title_candidates,
    write_set,
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
#: What a set's AI work raises instead of giving cards: its paths left retry, fail or (lease lost) stop.
_RAISED_FROM_A_PATH: tuple[type[Exception], ...] = (*TEMPORARY_ERRORS, JobFailed, LeaseLost)


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

    def write_set(
        self, slots: Sequence[tuple[str, dict[str, Any]]], last_try: bool, epoch: int = 0
    ) -> Iterator[tuple[str, PathOutcome | Exception]]:
        """Each path's outcome by its id as soon as it is final, the set ((slot label, path)) written in one
        set of AI calls (write_set; `epoch`, the set's job epoch, rotates its evidence links). The paths left
        when the AI cannot go on get the outage to retry; a whole answer unusable twice is one too, but on the
        job's `last_try` each of them gets a failure card. One cut off at the model's full room (or too long
        to send) gets them at once: a retry would be cut off again."""
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
            for label, written in write_set(self._chat, list(briefs.items()), epoch):
                brief = left.pop(label)
                yield path_ids[label], written if isinstance(written, PathFailure) else (brief, written)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            reason = shorten_text(str(exc), Writing.PROBLEM_MAX_CHARS)
            final = last_try or isinstance(exc, TruncatedAiAnswer)
            failure = PathFailure(ErrorCode.GENERATION_FAILED, reason) if final else Unavailable(reason)
            yield from ((path_ids[label], failure) for label in left)
        except _RAISED_FROM_A_PATH as exc:
            yield from ((path_ids[label], exc) for label in left)
        except Exception:  # a fault in one set must not cost the run its other sets
            log.exception(LogEvent.WRITER_PATH_FAILED, paths=[path_ids[label] for label in left])
            message = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            yield from ((path_ids[label], PathFailure(ErrorCode.INTERNAL_ERROR, message)) for label in left)

    def _brief(self, path: dict[str, Any]) -> WriterBrief | PathFailure:
        """A path's brief in its style, with its threat's actions; a path the plan cannot support fails for
        good, with no AI call."""
        try:
            style = path_style(self.threats, path, self._style)
            return build_brief(self.threats, path, self._context, self._budget, self._live, style=style)
        except PathNotWritable as exc:
            return PathFailure(exc.code, exc.message, final=True)
        except Exception:  # one path's fault must not cost the run its other paths
            log.exception(LogEvent.WRITER_PATH_FAILED, path_id=path["path_id"])
            unexpected = ErrorMessage.JOB_UNEXPECTED.format(record_id=self._run_id)
            return PathFailure(ErrorCode.INTERNAL_ERROR, unexpected)


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
    """Log one saved record; count a written one (saved once: a card is counted with its path's state)."""
    shown = {"path_id": record["path_id"], "status": record["status"], "replaces": record.get("replaces")}
    log.info(LogEvent.WRITER_SCENARIO_SAVED, saved=saved, blocker=reason, **shown)
    if saved and record["status"] == ScenarioStatus.DONE:
        metrics.SCENARIOS.labels(ScenarioOutcome.WRITTEN).inc()


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
        """The batch's paths still to write; a path an earlier delivery wrote is served here with no AI call,
        one it settled is not written again (`replaces`: a regenerate's versions to replace, each written
        afresh; its other paths are outage cards' paths, written again even once given up)."""
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
        settled = self._progress.settled_by_this_job
        return to_write + [
            key for key in open_paths if is_still_to_write(paths[key], reopen=regenerate) and not settled(key)
        ]

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
        card = ScenarioOutcome(record["status"])  # counted with the path's state, by the write that is taken
        if reason == ErrorCode.UNAVAILABLE and state["attempts"] < Generation.MAX_PATH_ATTEMPTS:
            self._progress.leave_for_next_set(path_id, state, card)  # an outage passes: a later set writes it
            return
        # The writer's own retry is off; uncomment to retry a blocked path later, up to MAX_PATH_ATTEMPTS.
        # if not (final or state["attempts"] >= Generation.MAX_PATH_ATTEMPTS):
        #     self._progress.record({path_id: state | {"abandoned": False}})
        #     return
        outage = outcome.reason if isinstance(outcome, PathFailure) else None  # its card's: regenerable
        self._progress.abandon(path_id, state | {"abandoned": True}, outage or reason, self._threats, card)

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
        log.warning(LogEvent.WRITER_REGENERATE_FAILED, scenario_id=target_id, code=code, message=message)
        error = {"code": code, "message": message, "at": utc_now()}
        error |= {"reason": reason} if reason else {}
        changes = {"regenerate_error": error, "updated_at": error["at"]}
        self._scenarios.update(changes, _id=target_id, newest=True)
