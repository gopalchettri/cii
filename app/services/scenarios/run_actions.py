"""Giving a finished run more work: next set writes the next NEXT_SET_SIZE selected paths (owner 2026-10-11:
scenarios are written set by set, only when asked; a path an interruption left unwritten comes first), and
regenerate writes a new version of chosen scenarios.

Both replace the run's job in ONE conditional update on the epoch and state they read, so of two clicks, or a
click and a running worker, exactly one wins; the write job (tsg_write_scenarios) then does the work. Neither
finds new threats nor goes past the frozen plan's selected paths."""

from typing import Any

from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ConflictReason,
    ReviewMessage,
    RunActionKind,
    RunClash,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.core.singletons import singleton
from app.core.tracing import traced
from app.data_access.job_control import JobControlRecords
from app.data_access.run_actions import RunActionRecords
from app.data_access.scenario_review import ScenarioReview
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.attack_paths.path_progress import set_and_first_batch, why_no_path_left
from app.engine.scenarios.review_checks import why_ids_cannot_be_regenerated
from app.models.api_clients import Principal
from app.models.review import RunActionStarted, ScenarioIdsRequest
from app.models.scenarios import SessionStatus
from app.realtime.publisher import publish_session_status
from app.services.audit import audit_target, caller_actor, record_audit
from app.services.scenarios.review import check_review_open
from app.worker.celery_app import send_job

_NONE_LEFT = {
    ConflictReason.NOTHING_LEFT: ReviewMessage.NOTHING_LEFT,
    ConflictReason.TARGET_REACHED: ReviewMessage.TARGET_REACHED,
    ConflictReason.SCENARIOS_ABANDONED: ReviewMessage.SCENARIOS_ABANDONED,
}


class RunActions:
    def __init__(
        self,
        records: RunActionRecords,
        review: ScenarioReview,
        sessions: SessionRepository,
        controls: JobControlRecords,
    ) -> None:
        self._records, self._review, self._sessions, self._controls = records, review, sessions, controls

    @traced("run.next_set")
    def next_set(self, principal: Principal, run: SessionStatus) -> RunActionStarted:
        """The next NEXT_SET_SIZE selected, unwritten, not abandoned paths, best rank first, as the job's set:
        the write job writes them and stops. 409 with the exact reason when none is left."""
        check_review_open(run)
        record = self._records.find_for_action(run.session_id, with_paths=True)
        paths = (record.get("plan") or {}).get("paths") or []
        asked, batch = set_and_first_batch(paths, get_settings().next_set_size)
        if not asked:
            if resumed := self._resume_controls(record["_id"]):  # G214: only its stopped controls were left
                publish_session_status(record["_id"])
                target = audit_target(AuditTarget.SESSION, record["_id"])
                after = {"controls_resumed": resumed}
                record_audit(AuditAction.RUN_NEXT_SET, caller_actor(principal), target, after=after)
                return RunActionStarted(epoch=record["job"]["epoch"])
            reason = why_no_path_left(paths)
            raise Conflict(_NONE_LEFT[reason].format(session_id=run.session_id), reason=reason)
        return self._queue_again(principal, record, RunActionKind.NEXT_SET, batch, asked)

    @traced("run.regenerate")
    def regenerate(
        self, principal: Principal, run: SessionStatus, request: ScenarioIdsRequest
    ) -> RunActionStarted:
        """A new version of each chosen scenario: the current written version of its path, one per path. 409
        scenarios_not_regenerable names every id at fault (nothing is queued)."""
        check_review_open(run)
        targets = self._review.find_targets(run.session_id, request.scenario_ids)
        errors = why_ids_cannot_be_regenerated(request.scenario_ids, targets)
        if errors:
            message = ReviewMessage.NOT_REGENERABLE
            raise Conflict(message, reason=ConflictReason.SCENARIOS_NOT_REGENERABLE, errors=errors)
        batch = [{"path_id": targets[sid]["path_id"], "replaces": sid} for sid in request.scenario_ids]
        record = self._records.find_for_action(run.session_id, with_paths=False)
        return self._queue_again(principal, record, RunActionKind.REGENERATE, batch)

    def _queue_again(
        self,
        principal: Principal,
        record: dict[str, Any],
        kind: RunActionKind,
        batch: list[dict[str, Any]],
        asked: list[str] | None = None,
    ) -> RunActionStarted:
        """The new job in one conditional update, then sent (a lost send is re-sent by the reaper), announced
        and audited."""
        clash = self._records.queue_again(record, kind, batch, asked)
        if clash is RunClash.ACTIVE_RUN:
            active_id = self._sessions.find_active_run_id(record["entity_id"], record["asset_id"])
            message = ReviewMessage.ASSET_BUSY.format(asset_id=record["asset_id"])
            raise Conflict(
                message, reason=ConflictReason.ASSET_BUSY, details={"active_session_id": active_id}
            )
        if clash is RunClash.CHANGED:
            message = ReviewMessage.GENERATION_IN_PROGRESS.format(session_id=record["_id"])
            raise Conflict(message, reason=ConflictReason.GENERATION_IN_PROGRESS)
        epoch = record["job"]["epoch"] + 1
        self._resume_controls(record["_id"])  # G214: a cancelled run resumed whole
        send_job(TaskName.WRITE_SCENARIOS, record["_id"], epoch)
        publish_session_status(record["_id"])
        action = AuditAction.RUN_NEXT_SET if kind == RunActionKind.NEXT_SET else AuditAction.RUN_REGENERATED
        target = audit_target(AuditTarget.SESSION, record["_id"])
        after = {"epoch": epoch, "batch": batch} | ({"set": asked} if asked else {})
        record_audit(action, caller_actor(principal), target, after=after)
        return RunActionStarted(epoch=epoch)

    def _resume_controls(self, session_id: str) -> int:
        """The controls a cancel stopped, queued again and sent at once (else they wait for the sweep)."""
        resumed = self._controls.resume_controls(session_id)
        if resumed:
            send_job(TaskName.MAP_CONTROLS, session_id, 0)  # the epoch is never checked for controls
        return resumed


@singleton
def get_run_actions() -> RunActions:
    db = get_mongodb()
    return RunActions(RunActionRecords(db), ScenarioReview(db), SessionRepository(db), JobControlRecords(db))
